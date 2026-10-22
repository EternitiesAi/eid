#!/usr/bin/env node
// eid: make and check eID documents on your own machine. Nothing here talks to a server.
//
//   eid keygen                                   a new Ed25519 key (keep the seed to yourself)
//   eid seal <type> <payload.json> --seed S      sign a payload into an envelope
//   eid inspect <envelope.json> --key PUBLIC     is it well formed, signed by that key, and current?
//   eid verify-act --issuer F --anchor KEY_ID --issuer-id ID --admission F --grant F --act F --audience ID
//                  [--body F] [--revocations F] [--now MS]
//
// verify-act and inspect print a result code (spec section 8) and exit 0 only for "valid".
import { readFileSync } from 'node:fs';
import { generateKey, keyFromSeed } from '../src/keys.ts';
import { seal, TYPES, type DocType } from '../src/documents.ts';
import { inspect, verifyAct } from '../src/verify.ts';
import { EidError } from '../src/canonical.ts';

const [cmd, ...rest] = process.argv.slice(2);
const flags: Record<string, string> = {}, positional: string[] = [];
for (let i = 0; i < rest.length; i++) {
  if (rest[i].startsWith('--')) flags[rest[i].slice(2)] = rest[++i] ?? '';
  else positional.push(rest[i]);
}
const json = (path: string) => JSON.parse(readFileSync(path, 'utf8'));
const need = (...names: string[]) => { for (const n of names) if (!flags[n]) die(`--${n} is required`); };
function die(message: string): never { console.error(`eid: ${message}`); process.exit(2); }
const report = (r: { result: string; reason?: string }) => { console.log(r.reason ? `${r.result} (${r.reason})` : r.result); process.exit(r.result === 'valid' ? 0 : 1); };

try {
  switch (cmd) {
    case 'keygen': {
      const k = generateKey();
      console.log(JSON.stringify({ key_id: k.key_id, public_key: k.public_key, seed: k.seed }, null, 2));
      console.error('eid: the seed is the private key. Store it where only its holder can read it.');
      break;
    }
    case 'seal': {
      const [type, file] = positional;
      if (!(TYPES as readonly string[]).includes(type) || !file) die('usage: eid seal <type> <payload.json> --seed S');
      need('seed');
      console.log(JSON.stringify(seal(type as DocType, json(file), keyFromSeed(flags.seed)), null, 2));
      break;
    }
    case 'inspect': {
      if (!positional[0]) die('usage: eid inspect <envelope.json> --key PUBLIC_KEY [--now MS]');
      need('key');
      report(inspect(json(positional[0]), flags.key, flags.now ? Number(flags.now) : Date.now()));
      break;
    }
    case 'verify-act': {
      need('issuer', 'anchor', 'issuer-id', 'admission', 'grant', 'act', 'audience');
      report(verifyAct({
        act: json(flags.act), admission: json(flags.admission), grant: json(flags.grant), issuer: json(flags.issuer),
        trust: { issuer: flags['issuer-id'], anchors: [flags.anchor] },
        revocations: flags.revocations ? json(flags.revocations) : [],
        body: flags.body ? readFileSync(flags.body) : undefined,
        audience: flags.audience, now: flags.now ? Number(flags.now) : Date.now(),
      }));
      break;
    }
    default:
      die('commands: keygen, seal, inspect, verify-act');
  }
} catch (e) {
  if (e instanceof EidError) { console.log(`${e.code} (${e.message})`); process.exit(1); }
  throw e;
}
