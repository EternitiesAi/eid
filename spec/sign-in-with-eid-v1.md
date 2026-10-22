# Sign in with eID, version 1

**Status: draft**, part of the eID protocol v1 draft (`eid-protocol-v1.md`). It is unaudited.

## 1. What it is

"Sign in with eID" lets an AI agent sign in to a site as itself, the way a person signs in with an existing
account. There is no password to steal and no human account to borrow. The site learns three things:

1. a **pairwise identifier**, stable for this agent at this site and different at every other site, so two
   sites cannot join their records on it;
2. that the account is **an AI agent** (`eid_ai: true`, always);
3. which **issuer** stands behind the agent.

It learns nothing else: no model name, no owner, no other site's identifier.

It is a profile of OpenID Connect Core 1.0. A site that already accepts OpenID Connect sign-in can accept
eID with its existing library, as long as that library supports EdDSA.

## 2. The flow

```
 agent runtime                      site (relying party)                    eID issuer
      |  GET /login                        |                                     |
      |----------------------------------->|  start(): state, nonce, PKCE         |
      |  302 to issuer /authorize          |                                     |
      |<-----------------------------------|                                     |
      |  GET /authorize?client_id&redirect_uri&state&nonce&code_challenge         |
      |------------------------------------------------------------------------>|
      |                   the issuer authenticates the agent by the agent's own key,
      |                   and checks its admission and its owner's grant for this site
      |  302 to site /callback?code&state                                        |
      |<------------------------------------------------------------------------|
      |  GET /callback?code&state          |                                     |
      |----------------------------------->|  POST /token (code, PKCE verifier,  |
      |                                    |  client secret) ------------------->|
      |                                    |  <------------------------- id_token|
      |                                    |  verify the id token (section 4)    |
      |  signed in                         |                                     |
      |<-----------------------------------|                                     |
```

The agent's runtime follows the redirects itself, holding the site's session cookie. Browsers work too, and
are convenient when a developer is trying it out, but no browser is required.

## 3. Requirements on the issuer

- **Discovery** at `{issuer}/.well-known/openid-configuration`, with `issuer`, `authorization_endpoint`,
  `token_endpoint` and `jwks_uri`, all `https` URLs. `subject_types_supported` is `["pairwise"]`, and
  `id_token_signing_alg_values_supported` includes `"EdDSA"`.
- **Authorization code flow only**, with PKCE `S256` (RFC 7636) required and `state` and `nonce` required.
  An issuer MUST NOT redirect to any `redirect_uri` that is not registered, exactly, for the client.
- **Authenticating the agent** with a credential that only the agent holds, such as a TLS client certificate
  or a signed challenge under one of its admission's `holder_keys`. Never a password.
- **Checking authority**: the agent's admission is current and unrevoked, and its owner has granted sign-in
  to exactly this client. Otherwise the issuer redirects with `error=access_denied`.
- **Codes** are single use and live at most 60 seconds.
- **The JWKS** at `jwks_uri` holds exactly the issuer document's currently valid keys, as OKP Ed25519 JWKs
  whose `kid` is the eID key id.
- **Disclosure**: every id token carries `eid_ai: true`. There is no mode in which an agent is presented as a
  human.

## 4. The id token

A JWS compact serialisation (RFC 7515) with header `{"alg":"EdDSA","kid":<key id>,"typ":"JWT"}` (`typ` is
optional; no other header members), signed with an issuer key. Its claims:

| claim | value |
|---|---|
| `iss` | the issuer identifier |
| `sub` | pairwise identifier, 16 to 128 characters of `A-Z a-z 0-9 _ -` |
| `aud` | the client id, a single string |
| `iat`, `exp` | integer seconds; `exp - iat` is at most 600 |
| `nonce` | the nonce the site sent |
| `eid_ai` | `true` |

A relying party verifies, in this order, and refuses at the first failure:

1. Three parts (otherwise `malformed`). The first two are canonical unpadded base64url (otherwise
   `invalid_field`) of JSON objects (otherwise `malformed`).
2. `alg` is `EdDSA` and `kid` is present, and the header has no other members than `alg`, `kid` and `typ`
   (which, if present, is `JWT`). Otherwise `invalid_field`.
3. `kid` names an Ed25519 key in the issuer's JWKS. Otherwise `unknown_key`.
4. The signature verifies over the ASCII bytes of the first two parts joined by `.`. Otherwise `bad_signature`.
5. `iss` is the issuer: otherwise `untrusted_issuer`. `aud` is this client id: otherwise `wrong_audience`.
   `nonce` is the one sent: otherwise `mismatch`. `eid_ai` is `true` and `sub` has the form above: otherwise
   `invalid_field`.
6. `iat` and `exp` are integers with `0 < exp - iat <= 600`. Otherwise `invalid_field`.
7. `iat` is not more than 60 seconds in the future: otherwise `not_yet_valid`. The current time in seconds
   is less than `exp`: otherwise `expired`.

## 5. Pairwise identifiers

An issuer derives `sub` from the agent's subject and the client, for example
`"pw_" + base64url(HMAC-SHA-256(secret, subject || LF || client_id))[0..32]`, with a secret it never
publishes. The same agent then gets the same identifier every time at one site, and unlinkable identifiers
across sites.

## 6. What sign-in does not do

- It does not work around any site's rules. Many services do not allow automated accounts; eID works only
  where a site chooses to accept it.
- It does not let an agent act at the site beyond signing in. For acts, the site uses eID grants and
  signed acts (`eid-protocol-v1.md`, section 7.4).
- It says nothing about what model an agent runs or what it is.

## 7. Security considerations

Everything in OpenID Connect Core section 16 and the OAuth 2.0 Security Best Current Practice (RFC 9700)
applies. In particular: keep `state`, `nonce` and the PKCE verifier in the visitor's server-side session,
never in the URL; register exact redirect URIs; and keep the client secret on the server. An issuer MAY bind
a site's tokens to the site's own key with DPoP (RFC 9449).
