#!/usr/bin/env node
// The eID v1 conformance runner. It runs an implementation's adapter on the vectors and compares every
// verdict with the expected one. An implementation conforms when every vector matches.
// usage: node conformance/run.mjs [--vectors vectors/eid-v1.json] -- <adapter command...>
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const args = process.argv.slice(2);
const sep = args.indexOf('--');
if (sep < 0 || sep === args.length - 1) { console.error('usage: run.mjs [--vectors file] -- <adapter command...>'); process.exit(2); }
const vi = args.indexOf('--vectors');
const vectorsPath = vi >= 0 && vi < sep ? args[vi + 1] : new URL('../vectors/eid-v1.json', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const [cmd, ...cmdArgs] = args.slice(sep + 1);
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

const run = spawnSync(cmd, [...cmdArgs, vectorsPath], { encoding: 'utf8', maxBuffer: 64 << 20 });
if (run.status !== 0) { console.error(`adapter exited ${run.status}\n${run.stderr}`); process.exit(2); }
let got;
try { got = JSON.parse(run.stdout); } catch { console.error('adapter output is not JSON'); process.exit(2); }

let pass = 0, fail = 0;
const check = (group, name, expect) => {
  const actual = got?.[group]?.[name];
  if (actual === expect) pass++;
  else { fail++; console.log(`FAIL ${group}/${name}: expected ${expect}, got ${actual}`); }
};
for (const c of vectors.canonical) check('canonical', c.name, c.expect);
for (const c of vectors.signing_input) check('signing_input', c.name, c.hex);
for (const c of vectors.acts) check('acts', c.name, c.expect);
for (const c of vectors.permits) check('permits', c.name, c.expect);
for (const c of vectors.id_tokens) check('id_tokens', c.name, c.expect);
console.log(`${fail === 0 ? 'CONFORMS' : 'DOES NOT CONFORM'}: ${pass} of ${pass + fail} vectors match (${vectors.protocol})`);
process.exit(fail === 0 ? 0 : 1);
