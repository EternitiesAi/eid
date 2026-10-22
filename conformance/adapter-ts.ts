// The TypeScript reference SDK as a conformance adapter. Any implementation can be tested the same
// way: a program that takes the vectors file as its one argument and prints its verdicts as JSON
// (see conformance/README.md). usage: node conformance/adapter-ts.ts vectors/eid-v1.json
import { readFileSync } from 'node:fs';
import { parseCanonical, EidError } from '../ts/src/canonical.ts';
import { signingInput } from '../ts/src/documents.ts';
import { verifyAct, verifyPermit } from '../ts/src/verify.ts';
import { verifyIdToken } from '../ts/src/signin.ts';

const v = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const code = (e: unknown) => e instanceof EidError ? e.code : 'malformed';
const out: Record<string, Record<string, string>> = { canonical: {}, signing_input: {}, acts: {}, permits: {}, id_tokens: {} };

for (const c of v.canonical) { try { parseCanonical(c.text); out.canonical[c.name] = 'canonical'; } catch (e) { out.canonical[c.name] = code(e); } }
for (const c of v.signing_input) out.signing_input[c.name] = signingInput(c.type, c.key_id, c.payload).toString('hex');
for (const c of v.acts) out.acts[c.name] = verifyAct(c.input).result;
for (const c of v.permits) out.permits[c.name] = verifyPermit({ ...c.input, consumed: new Set(c.input.consumed) }).result;
for (const c of v.id_tokens) { try { verifyIdToken(c.input.token, c.input); out.id_tokens[c.name] = 'valid'; } catch (e) { out.id_tokens[c.name] = code(e); } }
process.stdout.write(JSON.stringify(out) + '\n');
