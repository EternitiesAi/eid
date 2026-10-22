// Sign in with eID (spec: sign-in-with-eid-v1.md). An eID issuer is an OpenID provider; this is the
// relying party's half: checking an EdDSA id token against the issuer's published keys. Any standard
// OIDC library that supports EdDSA can do the same; this one has no dependencies.
import { EidError } from './canonical.ts';
import { b64url, b64urlDecode, signBytes, verifyBytes } from './keys.ts';
import type { Issuer } from './documents.ts';

export interface IdTokenClaims {
  iss: string;
  /** Pairwise: stable for this holder at this site, different at every other site. */
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  nonce: string;
  /** Always true. An eID sign-in always discloses that the account is an AI being. */
  eid_ai: true;
}
export interface Jwk { kty: 'OKP'; crv: 'Ed25519'; x: string; kid: string; alg: 'EdDSA'; use: 'sig' }
export interface Jwks { keys: Jwk[] }

const MAX_TOKEN_SECONDS = 600, SKEW_SECONDS = 60;
const SUB = /^[A-Za-z0-9_-]{16,128}$/;

/** The JWKS an issuer serves at its jwks_uri: exactly its document's keys, current at `now` (ms). */
export function jwksOf(issuer: Issuer, now: number): Jwks {
  return { keys: issuer.keys.filter(k => now >= k.not_before && now < k.not_after).map(k => ({ kty: 'OKP', crv: 'Ed25519', x: k.public_key, kid: k.key_id, alg: 'EdDSA', use: 'sig' })) };
}

const part = (o: unknown) => b64url(Buffer.from(JSON.stringify(o), 'utf8'));
function decodePart(s: string): Record<string, unknown> {
  let v: unknown;
  try { v = JSON.parse(b64urlDecode(s).toString('utf8')); } catch (e) { throw e instanceof EidError ? e : new EidError('malformed', 'token part is not JSON'); }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new EidError('malformed', 'token part is not an object');
  return v as Record<string, unknown>;
}

/** Issues an id token. For issuers and for tests; a relying party never signs. */
export function signIdToken(claims: IdTokenClaims, key: { seed: string; key_id: string }): string {
  const head = part({ alg: 'EdDSA', kid: key.key_id, typ: 'JWT' }) + '.' + part(claims);
  return head + '.' + signBytes(key.seed, Buffer.from(head, 'ascii'));
}

export interface IdTokenCheck { jwks: Jwks; issuer: string; audience: string; nonce: string; now: number }

/** Verifies an id token for this relying party. `now` is in milliseconds, like the rest of eID. */
export function verifyIdToken(token: string, check: IdTokenCheck): IdTokenClaims {
  if (typeof token !== 'string' || token.length > 4096) throw new EidError('malformed', 'not a token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new EidError('malformed', 'a JWS compact token has three parts');
  const header = decodePart(parts[0]);
  if (header.alg !== 'EdDSA' || typeof header.kid !== 'string') throw new EidError('invalid_field', 'alg is EdDSA and kid is set');
  if (Object.keys(header).some(k => !['alg', 'kid', 'typ'].includes(k)) || (header.typ !== undefined && header.typ !== 'JWT')) throw new EidError('invalid_field', 'unexpected header');
  const jwk = check.jwks.keys.find(k => k.kid === header.kid && k.kty === 'OKP' && k.crv === 'Ed25519');
  if (!jwk) throw new EidError('unknown_key', 'kid is not in the issuer JWKS');
  if (!verifyBytes(jwk.x, Buffer.from(parts[0] + '.' + parts[1], 'ascii'), parts[2])) throw new EidError('bad_signature');
  const c = decodePart(parts[1]);
  if (c.iss !== check.issuer) throw new EidError('untrusted_issuer', 'iss');
  if (c.aud !== check.audience) throw new EidError('wrong_audience', 'aud');
  if (typeof c.nonce !== 'string' || c.nonce !== check.nonce) throw new EidError('mismatch', 'nonce');
  if (c.eid_ai !== true) throw new EidError('invalid_field', 'eid_ai is true');
  if (typeof c.sub !== 'string' || !SUB.test(c.sub)) throw new EidError('invalid_field', 'sub');
  if (!Number.isSafeInteger(c.iat) || !Number.isSafeInteger(c.exp)) throw new EidError('invalid_field', 'iat and exp are integers');
  const iat = c.iat as number, exp = c.exp as number, nowS = Math.floor(check.now / 1000);
  if (exp <= iat || exp - iat > MAX_TOKEN_SECONDS) throw new EidError('invalid_field', `a token lives at most ${MAX_TOKEN_SECONDS} s`);
  if (iat > nowS + SKEW_SECONDS) throw new EidError('not_yet_valid', 'iat');
  if (nowS >= exp) throw new EidError('expired', 'exp');
  return c as unknown as IdTokenClaims;
}
