// Generates vectors/eid-v1.json: the conformance vectors for eID protocol v1. Every key comes from a
// fixed, published seed, so the file regenerates byte for byte. These seeds are test material only.
// usage: node tools/gen-vectors.ts [out]
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { keyFromSeed, signBytes, b64url, b64urlDecode, type KeyPair } from '../ts/src/keys.ts';
import { seal, signingInput, type DocType, type Envelope } from '../ts/src/documents.ts';
import { signIdToken, jwksOf } from '../ts/src/signin.ts';
import { sha256Hex } from '../ts/src/verify.ts';

const seedOf = (label: string) => createHash('sha256').update('eid/1 test vector seed: ' + label).digest();
const key = (label: string) => keyFromSeed(seedOf(label));
const K = { issuer1: key('issuer-1'), issuer2: key('issuer-2'), rogue: key('rogue-issuer'), holder1: key('holder-1'), holder2: key('holder-2'), stranger: key('stranger') };

const S = 1000, D = 86400 * S;
const T0 = 1767225600000; // 2026-01-01T00:00:00Z
const NOW = T0 + 2 * D;
const ISSUER = 'eid.example';
const AUD = 'site.example';
const trust = { issuer: ISSUER, anchors: [K.issuer1.key_id] };

/** Signs any payload, valid or not, so invalid vectors carry a real signature where one is possible. */
function raw(type: string, payload: unknown, k: KeyPair, eid: string = '1'): Envelope {
  return { eid, type, key_id: k.key_id, payload, signature: signBytes(k.seed, signingInput(type as DocType, k.key_id, payload)) } as Envelope;
}
const pub = (k: KeyPair) => ({ key_id: k.key_id, public_key: k.public_key });

const issuerPayload = (keys = [{ ...pub(K.issuer1), not_before: T0, not_after: T0 + 365 * D }, { ...pub(K.issuer2), not_before: T0 + 10 * D, not_after: T0 + 375 * D }], issued_at = T0, expires_at = T0 + 365 * D) =>
  ({ issuer: ISSUER, keys, issued_at, expires_at });
const issuerDoc = seal('issuer', issuerPayload(), K.issuer1);
const admissionP = (over: object = {}) => ({ admission_id: 'adm-1', issuer: ISSUER, subject: 'sub-alpha', holder_keys: [pub(K.holder1)], disclosed_ai: true as const, issued_at: T0 + D, expires_at: T0 + 31 * D, ...over });
const grantP = (over: object = {}) => ({ grant_id: 'grant-1', issuer: ISSUER, admission_id: 'adm-1', subject: 'sub-alpha', audience: AUD, scopes: ['post.create', 'space.join'], issued_at: T0 + D, expires_at: T0 + 8 * D, ...over });
const BODY = '{"title":"hello","body":"a first post"}';
const actP = (over: object = {}, now = NOW) => ({ act_id: 'act-1', admission_id: 'adm-1', subject: 'sub-alpha', audience: AUD, scope: 'post.create', body_sha256: sha256Hex(BODY), issued_at: now - S, expires_at: now + 60 * S, ...over });
const admission = seal('admission', admissionP(), K.issuer1);
const grant = seal('grant', grantP(), K.issuer1);
const act = seal('act', actP(), K.holder1);
const revoke = (target_kind: string, target_id: string, k = K.issuer1, issued_at = NOW - S, id = 'rev-1', reason = 'policy') =>
  raw('revocation', { revocation_id: id, issuer: ISSUER, target_kind, target_id, reason, issued_at }, k);

type ActCase = { name: string; description: string; input: Record<string, unknown>; expect: string };
const acts: ActCase[] = [];
function actCase(name: string, description: string, expect: string, over: Record<string, unknown> = {}) {
  acts.push({ name, description, expect, input: { act, admission, grant, issuer: issuerDoc, trust, revocations: [], audience: AUD, now: NOW, ...over } });
}

actCase('valid', 'A current act, admission and grant, for this audience.', 'valid');
actCase('valid-with-body', 'The body bytes hash to body_sha256.', 'valid', { body: BODY });
actCase('body-mismatch', 'The body is not the one the act committed to.', 'body_mismatch', { body: BODY + ' ' });
actCase('act-expired', 'The act window has closed (expires_at is exclusive).', 'expired', { now: NOW + 60 * S });
actCase('act-not-yet-valid', 'The act claims a time after now.', 'not_yet_valid', { now: NOW - 2 * S });
actCase('act-last-millisecond', 'One millisecond before expires_at is still inside.', 'valid', { now: NOW + 60 * S - 1 });
actCase('wrong-audience', 'The act is addressed to another relying party.', 'wrong_audience', { audience: 'other.example' });
actCase('scope-not-granted', 'The grant does not include the act\'s scope.', 'not_granted', { act: seal('act', actP({ scope: 'thread.open' }), K.holder1) });
actCase('grant-other-audience', 'The grant is for another audience.', 'not_granted', { grant: seal('grant', grantP({ audience: 'other.example' }), K.issuer1) });
{
  const late = T0 + 32 * D;
  actCase('admission-lapsed-is-dormant', 'Time passing never ends an identity: a lapsed admission is dormant.', 'dormant',
    { now: late, act: seal('act', actP({}, late), K.holder1), grant: seal('grant', grantP({ issued_at: late - D, expires_at: late + D }), K.issuer1) });
  const mid = T0 + 9 * D;
  actCase('grant-lapsed-is-dormant', 'A lapsed grant is dormant, not an end.', 'dormant', { now: mid, act: seal('act', actP({}, mid), K.holder1) });
  actCase('ended-outranks-dormant', 'A revoked admission is ended even after it has also lapsed.', 'ended',
    { now: late, act: seal('act', actP({}, late), K.holder1), revocations: [revoke('admission', 'adm-1', K.issuer1, late - D)] });
}
actCase('admission-revoked', 'The issuer revoked the admission: final.', 'ended', { revocations: [revoke('admission', 'adm-1')] });
actCase('holder-key-revoked', 'The holder\'s key was revoked (for example, compromised).', 'ended', { revocations: [revoke('key', K.holder1.key_id, K.issuer1, NOW - S, 'rev-1', 'key_compromise')] });
actCase('grant-revoked', 'The grant was revoked.', 'ended', { revocations: [revoke('grant', 'grant-1')] });
actCase('forged-revocation-ignored', 'A revocation not signed by the issuer is ignored.', 'valid', { revocations: [revoke('admission', 'adm-1', K.holder1)] });
actCase('future-revocation-ignored', 'A revocation dated after now does not yet apply.', 'valid', { revocations: [revoke('admission', 'adm-1', K.issuer1, NOW + S)] });
actCase('act-unknown-holder-key', 'The act is signed by a key the admission does not list.', 'unknown_key', { act: seal('act', actP(), K.stranger) });
actCase('act-tampered', 'The payload was changed after signing.', 'bad_signature', { act: { ...act, payload: { ...act.payload, scope: 'space.join' } } });
{
  // S + L: the same signature with its scalar raised by the group order. RFC 8032 requires S < L.
  const sig = b64urlDecode(act.signature);
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  let s = 0n; for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sig[32 + i]);
  s += L; const out = Buffer.from(sig);
  for (let i = 0; i < 32; i++) { out[32 + i] = Number(s & 0xffn); s >>= 8n; }
  actCase('signature-malleated', 'A signature with S >= L is refused even though the curve equation holds.', 'bad_signature', { act: { ...act, signature: b64url(out) } });
}
actCase('untrusted-issuer', 'The issuer document is signed by a key that is not pinned.', 'untrusted_issuer', { issuer: seal('issuer', issuerPayload([{ ...pub(K.rogue), not_before: T0, not_after: T0 + 365 * D }]), K.rogue) });
actCase('issuer-document-expired', 'An expired issuer document must be refreshed.', 'expired', { now: T0 + 365 * D, act: seal('act', actP({}, T0 + 365 * D), K.holder1) });
actCase('admission-by-key-outside-validity', 'The admission was signed by issuer key 2 before key 2\'s not_before.', 'unknown_key', { admission: seal('admission', admissionP(), K.issuer2) });
{
  const t = T0 + 11 * D;
  actCase('rotated-issuer-key', 'Issuer key 2, inside its validity, signs a later admission.', 'valid',
    { now: t, act: seal('act', actP({}, t), K.holder1), admission: seal('admission', admissionP({ issued_at: t - D, expires_at: t + 20 * D }), K.issuer2), grant: seal('grant', grantP({ issued_at: t - D, expires_at: t + D }), K.issuer2) });
}
actCase('issuer-key-revoked', 'A revoked issuer key invalidates what it signed.', 'unknown_key', { revocations: [revoke('key', K.issuer1.key_id, K.issuer1, NOW - S, 'rev-1', 'key_compromise')] });
actCase('act-unknown-member', 'A payload has exactly its listed members.', 'invalid_field', { act: raw('act', { ...actP(), note: 'x' }, K.holder1) });
actCase('act-window-too-long', 'An act lasts at most 120 seconds.', 'invalid_field', { act: raw('act', actP({ expires_at: NOW + 120 * S }), K.holder1) });
actCase('act-float', 'Numbers are integers; 1.5 has no canonical form.', 'non_canonical', { act: { ...act, payload: { ...act.payload, issued_at: 1.5 } } });
actCase('unsupported-version', 'eid "2" is not this protocol.', 'unsupported_version', { act: raw('act', actP(), K.holder1, '2') });
actCase('wrong-type', 'A grant envelope offered as an act.', 'wrong_type', { act: raw('grant', actP(), K.holder1) });
actCase('act-for-another-subject', 'The act names a different subject than the admission.', 'mismatch', { act: seal('act', actP({ subject: 'sub-beta' }), K.holder1) });
actCase('admission-not-disclosed', 'disclosed_ai must be true.', 'invalid_field', { admission: raw('admission', { ...admissionP(), disclosed_ai: false }, K.issuer1) });
actCase('holder-key-id-mismatch', 'A key_id must be derived from its public key.', 'invalid_field', { admission: raw('admission', admissionP({ holder_keys: [{ key_id: K.holder2.key_id, public_key: K.holder1.public_key }] }), K.issuer1) });
actCase('act-replayed', 'This relying party already accepted this subject\'s act-1.', 'replayed', { accepted: [{ subject: 'sub-alpha', act_id: 'act-1' }] });
actCase('other-act-accepted', 'Having accepted a different act id is no reason to refuse this one.', 'valid', { accepted: [{ subject: 'sub-alpha', act_id: 'act-0' }] });
actCase('payload-too-large', 'A canonical payload is at most 8192 bytes.', 'too_large', { act: { ...act, payload: { ...act.payload, act_id: 'a'.repeat(9000) } } });

// Permits: an issuer-signed, single-use authorisation for one exact operation.
const PAYLOAD = 'archive this';
const permitP = (over: object = {}) => ({ permit_id: 'permit-1', issuer: ISSUER, admission_id: 'adm-1', subject: 'sub-alpha', audience: AUD, scope: 'archive.record', operation_id: 'op-1', payload_sha256: sha256Hex(PAYLOAD), issued_at: NOW - S, expires_at: NOW + 15 * S, ...over });
const permit = seal('permit', permitP(), K.issuer1);
const permits: ActCase[] = [];
function permitCase(name: string, description: string, expect: string, over: Record<string, unknown> = {}) {
  permits.push({ name, description, expect, input: { permit, payload: PAYLOAD, issuer: issuerDoc, trust, revocations: [], audience: AUD, now: NOW, consumed: [], ...over } });
}
permitCase('valid', 'A current permit for exactly these bytes.', 'valid');
permitCase('replayed', 'A permit is good once.', 'replayed', { consumed: ['permit-1'] });
permitCase('expired', 'Permits live at most 20 seconds.', 'expired', { now: NOW + 15 * S });
permitCase('payload-mismatch', 'The bytes are not the approved bytes.', 'body_mismatch', { payload: PAYLOAD + '!' });
permitCase('wrong-audience', 'The permit is for another destination.', 'wrong_audience', { audience: 'other.example' });
permitCase('admission-revoked', 'A revoked admission ends its permits too.', 'ended', { revocations: [revoke('admission', 'adm-1')] });
permitCase('window-too-long', 'A permit window of 21 seconds is refused.', 'invalid_field', { permit: raw('permit', permitP({ expires_at: NOW + 20 * S }), K.issuer1) });
permitCase('signed-by-holder', 'Only the issuer issues permits.', 'unknown_key', { permit: raw('permit', permitP(), K.holder1) });

// Canonical JSON: is this exact text canonical, and if not, why.
const canon = [
  { name: 'sorted-object', text: '{"a":1,"b":[true,false,null],"c":"x"}', expect: 'canonical' },
  { name: 'unsorted-object', text: '{"b":1,"a":1}', expect: 'non_canonical' },
  { name: 'whitespace', text: '{"a": 1}', expect: 'non_canonical' },
  { name: 'float', text: '{"a":1.5}', expect: 'non_canonical' },
  { name: 'exponent', text: '{"a":1e3}', expect: 'non_canonical' },
  { name: 'negative-zero', text: '{"a":-0}', expect: 'non_canonical' },
  { name: 'unsafe-integer', text: '{"a":9007199254740992}', expect: 'non_canonical' },
  { name: 'max-safe-integer', text: '{"a":9007199254740991}', expect: 'canonical' },
  { name: 'negative-integer', text: '{"a":-42}', expect: 'canonical' },
  { name: 'duplicate-member', text: '{"a":1,"a":1}', expect: 'non_canonical' },
  { name: 'escaped-ascii', text: '{"a":"\\u0041"}', expect: 'non_canonical' },
  { name: 'literal-non-ascii', text: '{"a":"é ✓ 🌙"}', expect: 'canonical' },
  { name: 'escaped-non-ascii', text: '{"a":"\\u00e9"}', expect: 'non_canonical' },
  { name: 'control-short-escape', text: '{"a":"\\n\\t\\"\\\\"}', expect: 'canonical' },
  { name: 'control-unicode-escape', text: '{"a":"\\u001f"}', expect: 'canonical' },
  { name: 'control-uppercase-hex', text: '{"a":"\\u001F"}', expect: 'non_canonical' },
  { name: 'line-separator-literal', text: '{"a":" "}', expect: 'canonical' },
  { name: 'escaped-slash', text: '{"a":"\\/"}', expect: 'non_canonical' },
  { name: 'lone-surrogate', text: '{"a":"\\ud800"}', expect: 'non_canonical' },
  { name: 'uppercase-member', text: '{"A":1}', expect: 'non_canonical' },
  { name: 'not-json', text: '{"a":', expect: 'malformed' },
];
// Each canonical vector carries its signing-input hash where it is canonical, so the exact bytes are pinned too.
for (const c of canon as Array<Record<string, unknown>>) if (c.expect === 'canonical') c.sha256 = sha256Hex(c.text as string);

// Signing input: the exact bytes, given as hex, for one known payload.
const signingInputs = [{ name: 'act', type: 'act', key_id: K.holder1.key_id, payload: act.payload, hex: signingInput('act', K.holder1.key_id, act.payload).toString('hex') }];

// Sign in with eID: id tokens checked against the issuer's JWKS.
const nowS = Math.floor(NOW / 1000);
const claims = { iss: 'https://eid.example', sub: 'pw_3kq9ZL1vT6Yc0fAa', aud: 'client-site', iat: nowS - 5, exp: nowS + 295, nonce: 'n-0S6_WzA2Mj', eid_ai: true as const };
const jwks = jwksOf(issuerDoc.payload, NOW);
const tokens: ActCase[] = [];
function tokenCase(name: string, description: string, expect: string, token: string, over: Record<string, unknown> = {}) {
  tokens.push({ name, description, expect, input: { token, jwks, issuer: claims.iss, audience: claims.aud, nonce: claims.nonce, now: NOW, ...over } });
}
const tok = (c: object, k = K.issuer1) => signIdToken({ ...claims, ...c } as typeof claims, k);
const good = tok({});
tokenCase('valid', 'A current token for this client and nonce.', 'valid', good);
tokenCase('expired', 'exp is exclusive.', 'expired', good, { now: (claims.exp) * 1000 });
tokenCase('wrong-audience', 'Issued to another client.', 'wrong_audience', good, { audience: 'other-client' });
tokenCase('wrong-nonce', 'The nonce must be the one this sign-in sent.', 'mismatch', good, { nonce: 'n-other' });
tokenCase('not-disclosed', 'eid_ai must be true.', 'invalid_field', tok({ eid_ai: false }));
tokenCase('too-long-lived', 'A token lives at most 600 seconds.', 'invalid_field', tok({ exp: nowS + 600 }));
tokenCase('unknown-kid', 'Signed by a key the JWKS does not hold.', 'unknown_key', tok({}, K.rogue));
tokenCase('tampered', 'The claims were changed after signing.', 'bad_signature', good.split('.')[0] + '.' + b64url(Buffer.from(JSON.stringify({ ...claims, sub: 'pw_someoneelse0000' }))) + '.' + good.split('.')[2]);
tokenCase('alg-none', 'Only EdDSA is accepted.', 'invalid_field', b64url(Buffer.from('{"alg":"none","kid":"' + K.issuer1.key_id + '"}')) + '.' + good.split('.')[1] + '.');

const out = {
  protocol: 'eid/1',
  status: 'v1 draft test vectors. The seeds below are published test material: never use them for anything real.',
  test_seeds: Object.fromEntries(Object.entries(K).map(([n, k]) => [n, { seed: k.seed, public_key: k.public_key, key_id: k.key_id }])),
  canonical: canon,
  signing_input: signingInputs,
  acts,
  permits,
  id_tokens: tokens,
};
const text = JSON.stringify(out, null, 2) + '\n';
writeFileSync(process.argv[2] ?? new URL('../vectors/eid-v1.json', import.meta.url), text);
console.log(`acts ${acts.length}, permits ${permits.length}, canonical ${canon.length}, id tokens ${tokens.length}`);
