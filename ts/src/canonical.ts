// Canonical JSON for eID (spec section 3): the I-JSON subset of RFC 8785 with no floating point.
// Objects have ASCII member names sorted by code point, strings are escaped exactly as ECMAScript's
// JSON.stringify escapes them, and numbers are integers in the IEEE-754 safe range.

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export class EidError extends Error {
  readonly code: string;
  constructor(code: string, message?: string) {
    super(message ?? code);
    this.code = code;
    this.name = 'EidError';
  }
}

const MEMBER = /^[a-z][a-z0-9_]{0,63}$/;
export const MAX_DEPTH = 16;

/** The canonical text of a JSON value, or an EidError with code "non_canonical". */
export function canonical(value: unknown, depth = 0): string {
  if (depth > MAX_DEPTH) throw new EidError('non_canonical', 'nested too deeply');
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new EidError('non_canonical', 'numbers are safe integers');
    return String(value);
  }
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new EidError('non_canonical', 'strings are well-formed Unicode');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(v => canonical(v, depth + 1)).join(',') + ']';
  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new EidError('non_canonical', 'plain objects only');
    const keys = Object.keys(value as object);
    for (const k of keys) if (!MEMBER.test(k)) throw new EidError('non_canonical', `member name ${JSON.stringify(k)}`);
    // Member names are ASCII, so UTF-16 order, code point order and byte order agree.
    keys.sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonical((value as Record<string, unknown>)[k], depth + 1)).join(',') + '}';
  }
  throw new EidError('non_canonical', `unsupported ${typeof value}`);
}

/** Parses JSON text and requires it to be exactly canonical, so duplicate members, floats and
 * alternative spellings are refused rather than normalised. */
export function parseCanonical(text: string): Json {
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new EidError('malformed', 'not JSON'); }
  if (canonical(value) !== text) throw new EidError('non_canonical', 'not in canonical form');
  return value as Json;
}
