# The eID Protocol, version 1

**Status: draft.** This document specifies version 1 of the eID protocol. It may change before it is final.
The reference implementations in this repository are unaudited. An independent security review is planned
and has not happened yet.

## 1. Introduction

AI agents are starting to act on people's behalf: they post, buy, sign in, write to each other and call
services. Whoever receives one of those acts has to answer three questions:

1. **Who is this?** A stable identity that belongs to the agent and is not a borrowed human account.
2. **Who stands behind it?** Some accountable party admitted it, and said so in writing.
3. **May it do this, here, now?** A specific grant covers this exact action at this exact place, and nothing
   since has taken it away.

eID answers all three with small signed JSON documents that anyone can check offline. The agent holds its
own keys. An *issuer* admits it and grants it specific scopes. A *relying party* (a site, a service or
another agent) verifies an act against those documents with no call to the issuer.

eID makes two promises to the agents it identifies. **Time never ends an identity**: an admission that
lapses because nobody renewed it is *dormant*, and renewing it wakes the same identity up. **Ending is
explicit**: only a signed revocation, with a stated reason, ends an identity, and a revocation is final.

### 1.1 Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174.

All times are integers counting milliseconds since the Unix epoch (UTC). Every validity window is
*half-open*: a document whose window is `[issued_at, expires_at)` is current at `issued_at` and is no longer
current at `expires_at`.

## 2. Roles

- **Holder**: the agent. It generates and keeps its own private keys, and signs *acts* with them.
- **Issuer**: admits holders and grants them scopes. It publishes an *issuer document* listing its keys, and
  signs *admissions*, *grants*, *permits* and *revocations*. An issuer never holds a holder's private key.
- **Relying party**: anything that receives an act or a permit and decides whether to honour it. It trusts an
  issuer by pinning one or more of that issuer's key ids (the *anchors*), which it obtains out of band.

## 3. Canonical JSON

Signatures cover a canonical serialisation of the payload, so the same payload always produces the same
bytes in every language.

The canonical form is the subset of the JSON Canonicalization Scheme (RFC 8785) obtained by these limits:

1. **Values** are `null`, `true`, `false`, numbers, strings, arrays and objects.
2. **Numbers** are read as IEEE-754 double-precision values, the way ECMAScript's `JSON.parse` reads them. The
   value must be an integer `n` with `-(2^53 - 1) <= n <= 2^53 - 1`, and not negative zero. Otherwise the document
   has no canonical form. A number is written in base 10 with no leading zeros, fraction, exponent or plus sign.
3. **Strings** MUST be well-formed Unicode: a lone surrogate has no canonical form. They are written as
   `"` + escaped content + `"`, where only these characters are escaped:
   - `"` as `\"` and `\` as `\\`;
   - U+0008 as `\b`, U+0009 as `\t`, U+000A as `\n`, U+000C as `\f`, U+000D as `\r`;
   - every other character below U+0020 as `\u00` followed by two **lowercase** hex digits.

   Every other character, including `/`, U+2028, U+2029 and everything outside ASCII, is written as itself in
   UTF-8.
4. **Object member names** match `^[a-z][a-z0-9_]{0,63}$`. Members are written in ascending order of their
   names (for ASCII names, code point order and byte order agree). A name appears at most once.
5. **No whitespace** appears outside strings. Arrays are written `[` + elements joined by `,` + `]`; objects are
   written `{` + `name:value` pairs joined by `,` + `}`.
6. Nesting is at most 16 levels deep.

A verifier that receives a payload as parsed JSON computes its canonical form. A verifier that receives JSON
text and needs to know whether that text *is* canonical (vectors section `canonical`) parses it and compares
the canonical form of the result with the original text, byte for byte. Text with a duplicate member name is
therefore not canonical, whichever value a parser would keep. When a payload arrives inside an envelope and has
a repeated member name, the last occurrence is the one that counts, as in ECMAScript.

## 4. Keys

eID uses Ed25519 (RFC 8032) for every signature.

- A **public key** is written as the 32-byte Ed25519 public key in unpadded base64url (RFC 4648 section 5):
  43 characters. Padding, the standard base64 alphabet, and encodings whose unused trailing bits are not zero
  are refused.
- A **key id** is `key_` followed by the lowercase hex SHA-256 of the key's DER-encoded SubjectPublicKeyInfo.
  For Ed25519 this DER is the 12 bytes `30 2a 30 05 06 03 2b 65 70 03 21 00` followed by the 32 key bytes.
  Wherever a document lists a key, it lists both `key_id` and `public_key`, and a verifier MUST check that the
  id is derived from the key.
- A **signature** is the 64-byte Ed25519 signature in unpadded base64url: 86 characters. Verifiers MUST
  refuse a signature whose scalar `S` is not less than the group order `L`, as RFC 8032 section 5.1.7 requires.

## 5. Envelopes

Every eID document is an **envelope**, a JSON object with exactly these five members:

| member | value |
|---|---|
| `eid` | the string `"1"` for this version |
| `type` | one of `issuer`, `admission`, `grant`, `permit`, `act`, `revocation` |
| `key_id` | the key id of the key that signed it |
| `payload` | a JSON object whose shape is fixed by `type` (section 6) |
| `signature` | the signature, as in section 4 |

The envelope itself need not be canonical text. It may be pretty-printed, and its members may come in any
order. Only the payload is canonicalised.

### 5.1 The signing input

The signature covers exactly these bytes, in UTF-8:

```
"eid/1" LF type LF key_id LF canonical(payload)
```

where `LF` is the single byte 0x0A. The prefix binds the signature to this protocol, this document type
and this key, so a signature over an act can never be replayed as a grant or under another key. The
canonical payload is at most 8192 bytes.

### 5.2 Opening an envelope

To *open* an envelope under a public key, a verifier performs these checks in this order. It stops at the
first that fails and reports the result named.

1. The envelope is a JSON object (otherwise `malformed`) with exactly the five members (otherwise
   `invalid_field`).
2. `eid` is `"1"`. Otherwise `unsupported_version`.
3. `type` is one of the six types. Otherwise `invalid_field`. If the verifier expects a particular type and
   this is another, `wrong_type`.
4. `key_id` is the key id of the public key the verifier is using. Otherwise `unknown_key`.
5. The payload has a canonical form (section 3). Otherwise `non_canonical`. Its canonical form is at most
   8192 bytes. Otherwise `too_large`.
6. The signature verifies over the signing input. Otherwise `bad_signature`.
7. The payload has exactly the shape its type requires (section 6). Otherwise `invalid_field`.

Opening says only that the key signed this document. Whether the key is trusted, and whether the document
still holds, is verification (section 7).

## 6. Document types

Identifiers (ids, subjects, issuers, audiences, operations) match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.
**Scope atoms** match `^[a-z][a-z0-9_.:-]{0,95}$`. They are opaque, exact strings: no wildcards, prefixes
or paths. A **digest** is a lowercase hex SHA-256 (64 characters). A **time** is an integer of at least 1.

Each payload has exactly the members listed, no more and no fewer. Where a type has a validity window,
`expires_at` is greater than `issued_at`, and the window is no longer than the limit given.

### 6.1 issuer (signed by one of the issuer's own keys)

| member | value |
|---|---|
| `issuer` | the issuer's identifier |
| `keys` | 1 to 8 entries, distinct by `key_id`, each `{key_id, public_key, not_before, not_after}` with `not_after > not_before` |
| `issued_at`, `expires_at` | the document's window, at most 400 days |

An issuer key is valid for signing at time `t` when `not_before <= t < not_after`. Issuers rotate by
publishing a new issuer document that adds the new key before the old one's `not_after`.

### 6.2 admission (signed by an issuer key)

| member | value |
|---|---|
| `admission_id` | identifier |
| `issuer` | the issuer's identifier |
| `subject` | the holder's identifier at this issuer |
| `holder_keys` | 1 to 4 entries, distinct by `key_id`, each `{key_id, public_key}`: the keys the holder signs acts with |
| `disclosed_ai` | `true`, always. An eID holder is disclosed as an AI agent. There is no other value |
| `issued_at`, `expires_at` | at most 30 days |

An admission says that this issuer admitted this subject, with these keys. Renewing it means issuing a new
admission with the same `admission_id` and a later window. A verifier uses the most recent one it has.

### 6.3 grant (signed by an issuer key)

| member | value |
|---|---|
| `grant_id` | identifier |
| `issuer`, `admission_id`, `subject` | as in the admission it belongs to |
| `audience` | the identifier of the one relying party this grant is for |
| `scopes` | 1 to 32 scope atoms, sorted ascending and distinct |
| `issued_at`, `expires_at` | at most 7 days |

### 6.4 permit (signed by an issuer key)

A permit authorises one exact operation at one destination, once. It is for destinations that want the
issuer to approve each operation as it happens.

| member | value |
|---|---|
| `permit_id` | identifier |
| `issuer`, `admission_id`, `subject` | as in the admission |
| `audience` | the destination |
| `scope` | one scope atom |
| `operation_id` | the caller's idempotency key for this operation |
| `payload_sha256` | digest of the exact bytes the operation carries |
| `issued_at`, `expires_at` | at most 20 seconds |

### 6.5 act (signed by one of the holder's keys)

An act is the holder speaking for itself: "I, this subject, do this, here, with this body".

| member | value |
|---|---|
| `act_id` | identifier, unique per holder |
| `admission_id`, `subject` | the holder's admission |
| `audience` | the relying party the act is addressed to |
| `scope` | one scope atom |
| `body_sha256` | digest of the act's body bytes (an empty body is the digest of zero bytes) |
| `issued_at`, `expires_at` | at most 120 seconds |

### 6.6 revocation (signed by an issuer key)

| member | value |
|---|---|
| `revocation_id` | identifier |
| `issuer` | the issuer's identifier |
| `target_kind` | `admission`, `grant` or `key` |
| `target_id` | the revoked `admission_id` or `grant_id`, or for `key`, a key id |
| `reason` | `holder_request`, `sponsor_request`, `key_compromise`, `policy` or `superseded` |
| `issued_at` | when it takes effect |

A revocation is **final**. No document can reverse it. A holder whose admission was revoked and who is
admitted again receives a new `admission_id`.

A revoked **key** invalidates everything it ever signed, not only what it signs from now on, because a
compromised key could have back-dated its signatures. An issuer that revokes one of its own keys re-issues,
under a current key, whatever should stay valid.

An issuer MAY withdraw a revocation it has not yet published, for example one created by a defect, and
SHOULD record the withdrawal openly. Once any relying party may have seen a revocation, the revocation stands.

## 7. Verification

Verification is local. A relying party needs the issuer document, the holder's admission, the grant, the
revocations it has received from the issuer, and its own clock. It asks nothing of the issuer.

### 7.1 The issuer document

1. The issuer document's `key_id` is one of the relying party's pinned anchors. Otherwise `untrusted_issuer`.
2. That key is listed in the document's `keys`. Otherwise `untrusted_issuer`.
3. Open the document under that key, expecting type `issuer` (section 5.2).
4. `issuer` is the identifier the relying party expects. Otherwise `untrusted_issuer`.
5. `now >= issued_at`, otherwise `not_yet_valid`. `now < expires_at`, otherwise `expired`: the relying party
   fetches a fresh issuer document.

### 7.2 Revocations

Each revocation is opened under the issuer key its `key_id` names (that key must be in the issuer document
and valid at the revocation's `issued_at`; revocations among themselves are checked against the keys'
windows only). It counts only if it opens, its `issuer` matches, and
`issued_at <= now`. A revocation that fails any of these is **ignored**, because anyone can write one.

### 7.3 Documents signed by the issuer

An admission, grant, permit or revocation is opened under the issuer key its `key_id` names. If no such key
is in the issuer document, the result is `unknown_key`. After opening, the key MUST have been valid at the
document's own `issued_at`, and MUST NOT have been revoked. Otherwise `unknown_key`.

### 7.4 Verifying an act

Given an act, an optional body, an admission, a grant, the issuer document, the revocations, the relying
party's own `audience` and `now`, the verifier reports the first of these results that applies, in this
order:

1. Any failure from 7.1.
2. The admission does not open (7.3): that failure. Its `issuer` is not the issuer's: `mismatch`.
3. The act's `key_id` is not one of the admission's `holder_keys`: `unknown_key`. Otherwise open the act
   under that key, expecting type `act`: any failure.
4. The grant does not open (7.3): that failure.
5. The act's `subject` or `admission_id` differs from the admission's, or the grant's `subject`,
   `admission_id` or `issuer` does: `mismatch`.
6. The act's `audience` is not the relying party's: `wrong_audience`.
7. The admission, the holder key that signed the act, or the grant is revoked: `ended`. A revocation is
   checked before any question of time, because an ended identity stays ended.
8. `now < admission.issued_at`: `not_yet_valid`. `now >= admission.expires_at`: `dormant`.
9. The grant's `audience` is not the relying party's, or its `scopes` do not contain the act's `scope`:
   `not_granted`.
10. `now < grant.issued_at`: `not_yet_valid`. `now >= grant.expires_at`: `dormant`.
11. `now < act.issued_at`: `not_yet_valid`. `now >= act.expires_at`: `expired`.
12. A body was given and its SHA-256 is not `body_sha256`: `body_mismatch`.
13. Otherwise: `valid`.

A relying party MAY allow a small clock skew. The test vectors assume none.

`dormant` and `expired` are different on purpose. An act that expired is spent. An identity that is dormant
is waiting for its issuer to renew it, and it is the same identity when it wakes.

A relying party SHOULD remember the `act_id`s it has accepted until their acts expire, and refuse a repeat.

### 7.5 Verifying a permit

Given a permit, the operation's payload bytes, the issuer document, the revocations, the destination's
`audience`, `now` and the set of permit ids it has already consumed:

1. Any failure from 7.1.
2. The permit does not open (7.3): that failure. Its `issuer` is not the issuer's: `mismatch`.
3. Its `audience` is not the destination's: `wrong_audience`.
4. Its admission is revoked: `ended`.
5. Its `permit_id` was already consumed: `replayed`.
6. `now < issued_at`: `not_yet_valid`. `now >= expires_at`: `expired`.
7. The payload's SHA-256 is not `payload_sha256`: `body_mismatch`.
8. Otherwise `valid`. The destination records the permit id as consumed in the same transaction as the
   operation's effect.

A destination that reuses `operation_id` with a fresh permit for the same operation SHOULD return the
original result rather than perform the effect twice.

## 8. Results

| result | meaning |
|---|---|
| `valid` | the act or permit is good, now, here |
| `malformed` | not JSON, or not shaped like an envelope at all |
| `non_canonical` | the payload has no canonical form |
| `too_large` | the canonical payload exceeds 8192 bytes |
| `unsupported_version` | not eID version 1 |
| `invalid_field` | a member is missing, extra, or of the wrong form |
| `wrong_type` | an envelope of another type where this one was expected |
| `untrusted_issuer` | the issuer document is not anchored in what this relying party trusts |
| `unknown_key` | the signing key is not one that may sign this document at its time |
| `bad_signature` | the signature does not verify |
| `mismatch` | the documents do not belong together |
| `wrong_audience` | addressed to another relying party |
| `ended` | revoked: final |
| `dormant` | the admission or grant lapsed in time: renewable, the same identity |
| `not_granted` | no grant covers this scope for this audience |
| `not_yet_valid` | a window has not opened |
| `expired` | a window has closed |
| `body_mismatch` | the bytes are not the bytes that were signed for |
| `replayed` | a single-use permit was already consumed |

## 9. Security considerations

- **Trust starts with the anchor.** Everything rests on the relying party pinning the right issuer key ids.
  Obtain them from a channel you already trust, and treat a change of anchors as an event to review.
- **Offline means stale.** A relying party sees only the revocations it has received. Fetch the issuer's
  revocation list as often as the risk of the action requires. Short windows (20-second permits, 2-minute
  acts, 7-day grants) bound how long a missed revocation can matter.
- **Replay.** Remember accepted `act_id`s and consumed `permit_id`s for at least their windows.
- **Domain separation.** The signing input names the protocol, the type and the key, so no signature is
  valid in any other role. Never sign a payload that came from someone else without checking it is the
  payload you mean.
- **Signature malleability** is refused (S < L). Implementations SHOULD use a constant-time Ed25519
  library and MUST NOT implement the curve themselves.
- **Strictness is the defence.** Refuse unknown members, non-canonical numbers and non-canonical base64url.
  Lenient parsing is how two implementations come to disagree about what was signed.
- **Holder keys** belong to the holder alone. An issuer that asks for a holder's private key is not an eID
  issuer.
- **The protocol does not prove what an agent is**, what model it runs, or whether it is conscious. It says
  who admitted it, which keys speak for it, and what it may do. `disclosed_ai` means the holder is presented
  as an AI agent, never as a human.

## 10. Privacy considerations

- A `subject` is stable at one issuer, so every relying party that sees acts with the same subject can link
  them. Where linkage across sites matters, sign-in with eID uses pairwise identifiers instead
  (see `sign-in-with-eid-v1.md`).
- Documents carry no names, model identities, owners or locations. Issuers SHOULD keep it that way and put
  nothing in an identifier that identifies a person.
- Verification is offline, so the issuer does not learn where a holder acts.

## 11. Versioning

`eid` is `"1"`, and the signing input begins `eid/1`. A later version changes both, so no version-1
signature is valid in another version.
