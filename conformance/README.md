# Conformance

An implementation of eID v1 conforms when it reaches the expected result on every vector in
[`vectors/eid-v1.json`](../vectors/eid-v1.json).

```sh
node conformance/run.mjs -- node conformance/adapter-ts.ts       # the TypeScript SDK
node conformance/run.mjs -- go/eid-verify conformance           # the Go verifier (go build -o go/eid-verify ./go/cmd/eid-verify)
node conformance/run.mjs -- <your program>                       # yours
```

## Writing an adapter

Your program receives the path of the vectors file as its last argument and prints one JSON object:

```json
{
  "canonical":     { "<vector name>": "canonical" | "<result code>" },
  "signing_input": { "<vector name>": "<lowercase hex of the signing input bytes>" },
  "acts":          { "<vector name>": "<result code>" },
  "permits":       { "<vector name>": "<result code>" },
  "id_tokens":     { "<vector name>": "<result code>" }
}
```

What each group asks:

| group | input | your answer |
|---|---|---|
| `canonical` | `text`: JSON text | `canonical` if the text is exactly canonical (spec section 3), else the result code: `non_canonical` or `malformed` |
| `signing_input` | `type`, `key_id`, `payload` | the hex of the signing input (spec section 5.1) |
| `acts` | `input`: `act`, `admission`, `grant`, `issuer`, `trust`, `revocations`, `audience`, `now`, optional `body` (UTF-8 text) | the result of verifying the act (spec section 7.4) |
| `permits` | `input`: `permit`, `payload` (UTF-8 text), `issuer`, `trust`, `revocations`, `audience`, `now`, `consumed` (permit ids) | the result of verifying the permit (spec section 7.5) |
| `id_tokens` | `input`: `token`, `jwks`, `issuer`, `audience`, `nonce`, `now` (ms) | `valid` or the result code (`sign-in-with-eid-v1.md` section 4) |

`trust` is `{ "issuer": <id>, "anchors": [<key id>...] }`.

Every key in the vectors comes from a published seed (`test_seeds`), and `tools/gen-vectors.ts` regenerates the
file byte for byte. The seeds are test material: anyone can sign with them.

## Found a disagreement?

If your implementation and the vectors disagree and you believe the spec supports you, that is a bug in the spec
or the vectors, and we want to hear about it. Open an issue with the vector name and the section you are reading.
