// The six eID document types and their exact shapes (spec sections 5 and 6). A payload has exactly
// the members listed for its type, each of the stated form; anything else is refused.
import { canonical, EidError, type Json } from './canonical.ts';
import { b64urlDecode, keyIdOf, signBytes, verifyBytes } from './keys.ts';

export const PROTOCOL = 'eid/1';
export const TYPES = ['issuer', 'admission', 'grant', 'permit', 'act', 'revocation'] as const;
export type DocType = typeof TYPES[number];
export const REASONS = ['holder_request', 'sponsor_request', 'key_compromise', 'policy', 'superseded'] as const;
export const TARGETS = ['admission', 'grant', 'key'] as const;

export const MAX_PAYLOAD_BYTES = 8192;
const SECOND = 1000, DAY = 86400 * SECOND;
/** The longest window each type may claim, issued_at to expires_at. */
export const MAX_WINDOW: Record<DocType, number> = {
  issuer: 400 * DAY, admission: 30 * DAY, grant: 7 * DAY, permit: 20 * SECOND, act: 120 * SECOND, revocation: 0,
};

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SCOPE = /^[a-z][a-z0-9_.:-]{0,95}$/;
const KEY_ID = /^key_[0-9a-f]{64}$/;
const SHA256 = /^[0-9a-f]{64}$/;

export interface KeyRef { key_id: string; public_key: string }
export interface IssuerKey extends KeyRef { not_before: number; not_after: number }
export interface Issuer { issuer: string; keys: IssuerKey[]; issued_at: number; expires_at: number }
export interface Admission { admission_id: string; issuer: string; subject: string; holder_keys: KeyRef[]; disclosed_ai: true; issued_at: number; expires_at: number }
export interface Grant { grant_id: string; issuer: string; admission_id: string; subject: string; audience: string; scopes: string[]; issued_at: number; expires_at: number }
export interface Permit { permit_id: string; issuer: string; admission_id: string; subject: string; audience: string; scope: string; operation_id: string; payload_sha256: string; issued_at: number; expires_at: number }
export interface Act { act_id: string; admission_id: string; subject: string; audience: string; scope: string; body_sha256: string; issued_at: number; expires_at: number }
export interface Revocation { revocation_id: string; issuer: string; target_kind: typeof TARGETS[number]; target_id: string; reason: typeof REASONS[number]; issued_at: number }
export type Payload = Issuer | Admission | Grant | Permit | Act | Revocation;

export interface Envelope<P = Payload> { eid: '1'; type: DocType; key_id: string; payload: P; signature: string }

const bad = (what: string): never => { throw new EidError('invalid_field', what); };
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
function exactMembers(o: unknown, names: string[], what: string): Record<string, unknown> {
  if (!isObject(o)) bad(`${what} is an object`);
  const have = Object.keys(o as object).sort().join(','), want = [...names].sort().join(',');
  if (have !== want) bad(`${what} has exactly ${want}`);
  return o as Record<string, unknown>;
}
const id = (v: unknown, what: string) => { if (typeof v !== 'string' || !ID.test(v)) bad(`${what} is an identifier`); };
const time = (v: unknown, what: string) => { if (!Number.isSafeInteger(v) || (v as number) < 1) bad(`${what} is a positive integer of milliseconds`); };
const scope = (v: unknown, what: string) => { if (typeof v !== 'string' || !SCOPE.test(v)) bad(`${what} is a scope atom`); };
const sha = (v: unknown, what: string) => { if (typeof v !== 'string' || !SHA256.test(v)) bad(`${what} is a lowercase hex SHA-256`); };
function keyRef(v: unknown, what: string, extra: string[] = []): void {
  const k = exactMembers(v, ['key_id', 'public_key', ...extra], what);
  b64urlDecode(k.public_key as string, 32);
  if (typeof k.key_id !== 'string' || !KEY_ID.test(k.key_id) || keyIdOf(k.public_key as string) !== k.key_id) bad(`${what}.key_id matches its public_key`);
}
function window(p: Record<string, unknown>, type: DocType): void {
  time(p.issued_at, 'issued_at'); time(p.expires_at, 'expires_at');
  const span = (p.expires_at as number) - (p.issued_at as number);
  if (span <= 0 || span > MAX_WINDOW[type]) bad(`${/^[aeiou]/.test(type) ? 'an' : 'a'} ${type} lasts more than 0 and at most ${MAX_WINDOW[type]} ms`);
}
function list<T>(v: unknown, min: number, max: number, what: string, each: (x: unknown, w: string) => void): T[] {
  if (!Array.isArray(v) || v.length < min || v.length > max) bad(`${what} has ${min} to ${max} entries`);
  (v as unknown[]).forEach((x, i) => each(x, `${what}[${i}]`));
  return v as T[];
}

/** Checks a payload's shape for its type. Throws EidError("invalid_field") on any departure. */
export function checkPayload(type: DocType, p: unknown): void {
  switch (type) {
    case 'issuer': {
      const o = exactMembers(p, ['issuer', 'keys', 'issued_at', 'expires_at'], 'issuer');
      id(o.issuer, 'issuer'); window(o, type);
      const keys = list<IssuerKey>(o.keys, 1, 8, 'keys', (k, w) => {
        keyRef(k, w, ['not_before', 'not_after']);
        const r = k as IssuerKey; time(r.not_before, `${w}.not_before`); time(r.not_after, `${w}.not_after`);
        if (r.not_after <= r.not_before) bad(`${w} ends after it starts`);
      });
      if (new Set(keys.map(k => k.key_id)).size !== keys.length) bad('keys are distinct');
      return;
    }
    case 'admission': {
      const o = exactMembers(p, ['admission_id', 'issuer', 'subject', 'holder_keys', 'disclosed_ai', 'issued_at', 'expires_at'], 'admission');
      id(o.admission_id, 'admission_id'); id(o.issuer, 'issuer'); id(o.subject, 'subject'); window(o, type);
      if (o.disclosed_ai !== true) bad('disclosed_ai is true: an eID holder is always disclosed as an AI being');
      const keys = list<KeyRef>(o.holder_keys, 1, 4, 'holder_keys', (k, w) => keyRef(k, w));
      if (new Set(keys.map(k => k.key_id)).size !== keys.length) bad('holder_keys are distinct');
      return;
    }
    case 'grant': {
      const o = exactMembers(p, ['grant_id', 'issuer', 'admission_id', 'subject', 'audience', 'scopes', 'issued_at', 'expires_at'], 'grant');
      id(o.grant_id, 'grant_id'); id(o.issuer, 'issuer'); id(o.admission_id, 'admission_id'); id(o.subject, 'subject'); id(o.audience, 'audience'); window(o, type);
      const scopes = list<string>(o.scopes, 1, 32, 'scopes', scope);
      for (let i = 1; i < scopes.length; i++) if (!(scopes[i - 1] < scopes[i])) bad('scopes are sorted and distinct');
      return;
    }
    case 'permit': {
      const o = exactMembers(p, ['permit_id', 'issuer', 'admission_id', 'subject', 'audience', 'scope', 'operation_id', 'payload_sha256', 'issued_at', 'expires_at'], 'permit');
      id(o.permit_id, 'permit_id'); id(o.issuer, 'issuer'); id(o.admission_id, 'admission_id'); id(o.subject, 'subject'); id(o.audience, 'audience');
      scope(o.scope, 'scope'); id(o.operation_id, 'operation_id'); sha(o.payload_sha256, 'payload_sha256'); window(o, type);
      return;
    }
    case 'act': {
      const o = exactMembers(p, ['act_id', 'admission_id', 'subject', 'audience', 'scope', 'body_sha256', 'issued_at', 'expires_at'], 'act');
      id(o.act_id, 'act_id'); id(o.admission_id, 'admission_id'); id(o.subject, 'subject'); id(o.audience, 'audience');
      scope(o.scope, 'scope'); sha(o.body_sha256, 'body_sha256'); window(o, type);
      return;
    }
    case 'revocation': {
      const o = exactMembers(p, ['revocation_id', 'issuer', 'target_kind', 'target_id', 'reason', 'issued_at'], 'revocation');
      id(o.revocation_id, 'revocation_id'); id(o.issuer, 'issuer'); time(o.issued_at, 'issued_at');
      if (!(TARGETS as readonly unknown[]).includes(o.target_kind)) bad('target_kind is admission, grant or key');
      if (o.target_kind === 'key') { if (typeof o.target_id !== 'string' || !KEY_ID.test(o.target_id)) bad('a key target is a key id'); }
      else id(o.target_id, 'target_id');
      if (!(REASONS as readonly unknown[]).includes(o.reason)) bad('reason is one of ' + REASONS.join(', '));
      return;
    }
    default: bad('unknown type');
  }
}

/** The exact bytes an eID signature covers: "eid/1", the type and the key id, each followed by a
 * line feed, then the canonical payload. The prefix keeps a signature from meaning anything else. */
export function signingInput(type: DocType, keyId: string, payload: unknown): Buffer {
  const text = canonical(payload);
  if (Buffer.byteLength(text, 'utf8') > MAX_PAYLOAD_BYTES) throw new EidError('too_large', `a payload is at most ${MAX_PAYLOAD_BYTES} bytes`);
  return Buffer.from(`${PROTOCOL}\n${type}\n${keyId}\n${text}`, 'utf8');
}

export function seal<P extends Payload>(type: DocType, payload: P, key: { seed: string; key_id: string }): Envelope<P> {
  checkPayload(type, payload);
  return { eid: '1', type, key_id: key.key_id, payload, signature: signBytes(key.seed, signingInput(type, key.key_id, payload)) };
}

/** Checks an envelope's form and its signature under the given public key. Says nothing about
 * whether the key is trusted or the document is current: that is verification (verify.ts). */
export function open(envelope: unknown, publicKey: string, expectType?: DocType): Envelope {
  if (!isObject(envelope)) throw new EidError('malformed', 'an envelope is a JSON object');
  const e = exactMembers(envelope, ['eid', 'type', 'key_id', 'payload', 'signature'], 'envelope');
  if (e.eid !== '1') throw new EidError('unsupported_version', 'eid is "1"');
  if (!(TYPES as readonly unknown[]).includes(e.type)) throw new EidError('invalid_field', 'unknown type');
  if (expectType && e.type !== expectType) throw new EidError('wrong_type', `expected a ${expectType}`);
  if (typeof e.key_id !== 'string' || !KEY_ID.test(e.key_id) || keyIdOf(publicKey) !== e.key_id) throw new EidError('unknown_key', 'key_id is not this key');
  const input = signingInput(e.type as DocType, e.key_id, e.payload);
  if (typeof e.signature !== 'string' || !verifyBytes(publicKey, input, e.signature)) throw new EidError('bad_signature');
  checkPayload(e.type as DocType, e.payload);
  return e as unknown as Envelope;
}

export type { Json };
