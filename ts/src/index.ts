// eID reference SDK, protocol v1 draft. An unaudited reference implementation.
export { canonical, parseCanonical, EidError, type Json } from './canonical.ts';
export { keyFromSeed, generateKey, keyIdOf, signBytes, verifyBytes, b64url, b64urlDecode, type KeyPair } from './keys.ts';
export {
  PROTOCOL, TYPES, REASONS, TARGETS, MAX_WINDOW, MAX_PAYLOAD_BYTES, checkPayload, signingInput, seal, open,
  type DocType, type Envelope, type Payload, type Issuer, type IssuerKey, type KeyRef, type Admission, type Grant, type Permit, type Act, type Revocation,
} from './documents.ts';
export { verifyAct, verifyPermit, actKey, inspect, IssuerView, sha256Hex, type Result, type Trust, type Verdict, type ActInput, type PermitInput } from './verify.ts';
export { verifyIdToken, signIdToken, jwksOf, type IdTokenClaims, type Jwks } from './signin.ts';
