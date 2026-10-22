// Verification (spec section 7): deciding, offline, whether a signed act or permit is good right now.
// Every step is local: a relying party needs the issuer's document, the holder's admission, the
// grant, any revocations it has received, and a clock. No eID server is asked anything.
import { createHash } from 'node:crypto';
import { EidError } from './canonical.ts';
import { open, type Act, type Admission, type Envelope, type Grant, type Issuer, type IssuerKey, type Permit, type Revocation } from './documents.ts';

/** Every outcome a verifier can reach. Exactly one is returned, by the precedence in the spec. */
export type Result =
  | 'valid'
  | 'malformed' | 'non_canonical' | 'too_large' | 'unsupported_version' | 'invalid_field' | 'wrong_type'
  | 'untrusted_issuer' | 'unknown_key' | 'bad_signature' | 'mismatch' | 'wrong_audience'
  | 'ended' | 'dormant' | 'not_granted' | 'not_yet_valid' | 'expired' | 'body_mismatch' | 'replayed';

export interface Trust {
  /** The issuer identifier the relying party expects. */
  issuer: string;
  /** Key ids pinned out of band. The issuer document must be signed by one of them. */
  anchors: string[];
}

export interface Verdict<T = unknown> { result: Result; reason?: string; payload?: T }

const fail = (result: Result, reason?: string): Verdict<never> => ({ result, reason });
const errResult = (e: unknown): Verdict<never> => e instanceof EidError ? fail(e.code as Result, e.message) : fail('malformed', String(e));
const live = (t: { issued_at: number; expires_at: number }, now: number) => now >= t.issued_at && now < t.expires_at;
export const sha256Hex = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');

/** An opened issuer document, ready to answer "which key was valid at time t". */
export class IssuerView {
  readonly doc: Issuer;
  private readonly revokedKeys: Set<string>;
  readonly revocations: Revocation[];

  private constructor(doc: Issuer, revocations: Revocation[]) {
    this.doc = doc;
    this.revocations = revocations;
    this.revokedKeys = new Set(revocations.filter(r => r.target_kind === 'key').map(r => r.target_id));
  }

  /** Opens the issuer document under a pinned anchor and keeps only the revocations it signed. */
  static open(issuerEnvelope: unknown, trust: Trust, revocations: unknown[], now: number): IssuerView | Verdict<never> {
    let doc: Issuer;
    try {
      const e = issuerEnvelope as Envelope<Issuer>;
      if (typeof e !== 'object' || e === null || !trust.anchors.includes(e.key_id)) return fail('untrusted_issuer', 'not signed by a pinned anchor');
      const key = Array.isArray(e.payload?.keys) ? e.payload.keys.find(k => k?.key_id === e.key_id) : undefined;
      if (!key) return fail('untrusted_issuer', 'the anchor is not listed in the document');
      doc = open(e, key.public_key, 'issuer').payload as Issuer;
    } catch (err) { return errResult(err); }
    if (doc.issuer !== trust.issuer) return fail('untrusted_issuer', 'a different issuer');
    if (now < doc.issued_at) return fail('not_yet_valid', 'issuer document');
    if (now >= doc.expires_at) return fail('expired', 'issuer document: fetch a fresh one');
    const view = new IssuerView(doc, []);
    // A revocation that does not verify under the issuer is ignored: anyone could write one.
    const good: Revocation[] = [];
    for (const r of revocations) {
      try {
        const opened = view.openSigned(r, 'revocation');
        const rev = opened.payload as Revocation;
        if (rev.issuer === doc.issuer && rev.issued_at <= now) good.push(rev);
      } catch { /* ignored */ }
    }
    return new IssuerView(doc, good);
  }

  /** The issuer key named by key_id, if it was within its validity at time t and is not revoked. */
  keyAt(keyId: string, t: number): IssuerKey | undefined {
    const k = this.doc.keys.find(x => x.key_id === keyId);
    if (!k || t < k.not_before || t >= k.not_after || this.revokedKeys.has(keyId)) return undefined;
    return k;
  }

  /** Opens an envelope signed by one of this issuer's keys, at the time the document claims. */
  openSigned(envelope: unknown, type: 'admission' | 'grant' | 'permit' | 'revocation'): Envelope {
    const e = envelope as Envelope;
    if (typeof e !== 'object' || e === null) throw new EidError('malformed', 'not an envelope');
    const k = this.doc.keys.find(x => x.key_id === e.key_id);
    if (!k) throw new EidError('unknown_key', 'not an issuer key');
    const opened = open(e, k.public_key, type);
    const at = (opened.payload as { issued_at: number }).issued_at;
    if (!this.keyAt(k.key_id, at)) throw new EidError('unknown_key', 'the issuer key was not valid when this was signed');
    return opened;
  }

  revoked(kind: 'admission' | 'grant' | 'key', id: string): Revocation | undefined {
    return this.revocations.find(r => r.target_kind === kind && r.target_id === id);
  }
}

export interface ActInput {
  act: unknown;
  /** The bytes the act's body_sha256 commits to. Optional: without them the digest is not checked. */
  body?: Uint8Array | string;
  admission: unknown;
  grant: unknown;
  issuer: unknown;
  trust: Trust;
  revocations?: unknown[];
  /** This relying party's own audience identifier. */
  audience: string;
  now: number;
  /** Acts this relying party has accepted, keyed by actKey(). Optional: without it, replay is the caller's. */
  accepted?: { has(key: string): boolean };
}

/** The key an accepted act is remembered by: its subject and act id, joined by a line feed. */
export const actKey = (act: { subject: string; act_id: string }) => `${act.subject}\n${act.act_id}`;

/** Decides whether a holder's signed act is good, right now, for this audience. */
export function verifyAct(input: ActInput): Verdict<Act> {
  const view = IssuerView.open(input.issuer, input.trust, input.revocations ?? [], input.now);
  if (!(view instanceof IssuerView)) return view;
  let admission: Admission, act: Act, grant: Grant, holderKeyId: string;
  try { admission = view.openSigned(input.admission, 'admission').payload as Admission; } catch (e) { return errResult(e); }
  if (admission.issuer !== view.doc.issuer) return fail('mismatch', 'admission is from another issuer');
  try {
    const e = input.act as Envelope;
    if (typeof e !== 'object' || e === null) return fail('malformed', 'not an envelope');
    const k = admission.holder_keys.find(x => x.key_id === e.key_id);
    if (!k) return fail('unknown_key', 'not a key of this admission');
    act = open(e, k.public_key, 'act').payload as Act;
    holderKeyId = k.key_id;
  } catch (e) { return errResult(e); }
  try { grant = view.openSigned(input.grant, 'grant').payload as Grant; } catch (e) { return errResult(e); }

  if (act.subject !== admission.subject || act.admission_id !== admission.admission_id) return fail('mismatch', 'act is not for this admission');
  if (grant.subject !== admission.subject || grant.admission_id !== admission.admission_id || grant.issuer !== view.doc.issuer) return fail('mismatch', 'grant is not for this admission');
  if (act.audience !== input.audience) return fail('wrong_audience', 'act is addressed elsewhere');

  // A revocation is final, so it outranks every question of time.
  if (view.revoked('admission', admission.admission_id)) return fail('ended', 'admission revoked');
  if (view.revoked('key', holderKeyId)) return fail('ended', 'holder key revoked');
  if (view.revoked('grant', grant.grant_id)) return fail('ended', 'grant revoked');
  // Time passing never ends an identity. A lapsed admission or grant is dormant until renewed.
  if (input.now < admission.issued_at) return fail('not_yet_valid', 'admission');
  if (input.now >= admission.expires_at) return fail('dormant', 'admission lapsed; the holder renews it');
  if (grant.audience !== input.audience || !grant.scopes.includes(act.scope)) return fail('not_granted', `no grant for ${act.scope} here`);
  if (input.now < grant.issued_at) return fail('not_yet_valid', 'grant');
  if (input.now >= grant.expires_at) return fail('dormant', 'grant lapsed; the holder renews it');
  if (input.now < act.issued_at) return fail('not_yet_valid', 'act');
  if (input.now >= act.expires_at) return fail('expired', 'act');
  if (input.body !== undefined && sha256Hex(input.body) !== act.body_sha256) return fail('body_mismatch');
  if (input.accepted?.has(actKey(act))) return fail('replayed', 'this act was already accepted');
  return { result: 'valid', payload: act };
}

export interface PermitInput {
  permit: unknown;
  /** The bytes of the operation's payload. Required: a permit authorises exactly these bytes. */
  payload: Uint8Array | string;
  issuer: unknown;
  trust: Trust;
  revocations?: unknown[];
  audience: string;
  now: number;
  /** Permit ids this destination has already consumed. A permit is good once. */
  consumed?: { has(id: string): boolean };
}

/** Decides whether a destination may perform the operation an issuer-signed permit names. */
export function verifyPermit(input: PermitInput): Verdict<Permit> {
  const view = IssuerView.open(input.issuer, input.trust, input.revocations ?? [], input.now);
  if (!(view instanceof IssuerView)) return view;
  let permit: Permit;
  try { permit = view.openSigned(input.permit, 'permit').payload as Permit; } catch (e) { return errResult(e); }
  if (permit.issuer !== view.doc.issuer) return fail('mismatch', 'permit is from another issuer');
  if (permit.audience !== input.audience) return fail('wrong_audience');
  if (view.revoked('admission', permit.admission_id)) return fail('ended', 'admission revoked');
  if (input.consumed?.has(permit.permit_id)) return fail('replayed', 'permit already consumed');
  if (input.now < permit.issued_at) return fail('not_yet_valid', 'permit');
  if (input.now >= permit.expires_at) return fail('expired', 'permit');
  if (sha256Hex(input.payload) !== permit.payload_sha256) return fail('body_mismatch');
  return { result: 'valid', payload: permit };
}

/** One document on its own: is it well formed, signed by the key it names, and current? Used by the
 * CLI to inspect a single file. It does not decide authority; verifyAct and verifyPermit do. */
export function inspect(envelope: unknown, publicKey: string, now: number): Verdict {
  try {
    const e = open(envelope, publicKey);
    const p = e.payload as { issued_at: number; expires_at?: number };
    if (p.expires_at !== undefined && !live(p as { issued_at: number; expires_at: number }, now))
      return { result: now < p.issued_at ? 'not_yet_valid' : (e.type === 'admission' || e.type === 'grant' ? 'dormant' : 'expired'), payload: e.payload };
    return { result: 'valid', payload: e.payload };
  } catch (err) { return errResult(err); }
}
