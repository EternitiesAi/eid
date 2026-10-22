// Ed25519 keys as eID writes them (spec section 4): a public key is the 32 raw bytes in unpadded
// base64url, and its key id is "key_" + hex(SHA-256(SubjectPublicKeyInfo DER)).
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import { EidError } from './canonical.ts';

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const B64URL = /^[A-Za-z0-9_-]+$/;

/** Decodes unpadded base64url, refusing padding, other alphabets and non-canonical trailing bits. */
export function b64urlDecode(text: string, bytes?: number): Buffer {
  if (typeof text !== 'string' || !B64URL.test(text)) throw new EidError('invalid_field', 'not base64url');
  const out = Buffer.from(text, 'base64url');
  if (out.toString('base64url') !== text) throw new EidError('invalid_field', 'non-canonical base64url');
  if (bytes !== undefined && out.length !== bytes) throw new EidError('invalid_field', `expected ${bytes} bytes`);
  return out;
}
export const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

export function keyIdOf(publicKey: string): string {
  const raw = b64urlDecode(publicKey, 32);
  return 'key_' + createHash('sha256').update(Buffer.concat([SPKI_PREFIX, raw])).digest('hex');
}

function publicKeyObject(publicKey: string): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, b64urlDecode(publicKey, 32)]), format: 'der', type: 'spki' });
}

export interface KeyPair {
  /** The 32-byte private seed, unpadded base64url. Never leaves the holder. */
  seed: string;
  public_key: string;
  key_id: string;
}

/** A key pair from a 32-byte seed. Deterministic, so test vectors can be regenerated exactly. */
export function keyFromSeed(seed: Uint8Array | string): KeyPair {
  const raw = typeof seed === 'string' ? b64urlDecode(seed, 32) : Buffer.from(seed);
  if (raw.length !== 32) throw new EidError('invalid_field', 'a seed is 32 bytes');
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const public_key = b64url(spki.subarray(SPKI_PREFIX.length));
  return { seed: b64url(raw), public_key, key_id: keyIdOf(public_key) };
}

export function generateKey(): KeyPair {
  const { privateKey } = generateKeyPairSync('ed25519');
  const der = privateKey.export({ format: 'der', type: 'pkcs8' });
  return keyFromSeed(der.subarray(PKCS8_PREFIX.length));
}

export function signBytes(seed: string, message: Uint8Array): string {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, b64urlDecode(seed, 32)]), format: 'der', type: 'pkcs8' });
  return b64url(edSign(null, message, priv));
}

export function verifyBytes(publicKey: string, message: Uint8Array, signature: string): boolean {
  let sig: Buffer;
  try { sig = b64urlDecode(signature, 64); } catch { return false; }
  try { return edVerify(null, message, publicKeyObject(publicKey), sig); } catch { return false; }
}
