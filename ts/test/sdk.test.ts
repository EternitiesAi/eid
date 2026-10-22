import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { canonical, parseCanonical, EidError } from '../src/canonical.ts';
import { generateKey, keyFromSeed, keyIdOf } from '../src/keys.ts';
import { seal, open, signingInput } from '../src/documents.ts';
import { verifyAct, verifyPermit } from '../src/verify.ts';
import { verifyIdToken } from '../src/signin.ts';
import { SignIn } from '../src/rp.ts';
import { startDevIssuer } from '../../examples/sign-in/dev-issuer.ts';

const vectors = JSON.parse(readFileSync(new URL('../../vectors/eid-v1.json', import.meta.url), 'utf8'));
const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e) { return e instanceof EidError ? e.code : 'thrown'; } };

test('every vector gives its expected result', () => {
  for (const c of vectors.canonical) assert.equal(code(() => parseCanonical(c.text)) === 'ok' ? 'canonical' : code(() => parseCanonical(c.text)), c.expect, c.name);
  for (const c of vectors.signing_input) assert.equal(signingInput(c.type, c.key_id, c.payload).toString('hex'), c.hex, c.name);
  for (const c of vectors.acts) assert.equal(verifyAct(c.input).result, c.expect, c.name);
  for (const c of vectors.permits) assert.equal(verifyPermit({ ...c.input, consumed: new Set(c.input.consumed) }).result, c.expect, c.name);
  for (const c of vectors.id_tokens) assert.equal(code(() => verifyIdToken(c.input.token, c.input)) === 'ok' ? 'valid' : code(() => verifyIdToken(c.input.token, c.input)), c.expect, c.name);
});

test('the published test seeds produce the published keys', () => {
  for (const [name, k] of Object.entries(vectors.test_seeds) as [string, { seed: string; public_key: string; key_id: string }][]) {
    const again = keyFromSeed(k.seed);
    assert.equal(again.public_key, k.public_key, name);
    assert.equal(again.key_id, k.key_id, name);
    assert.equal(keyIdOf(k.public_key), k.key_id, name);
  }
});

test('canonical form sorts members and refuses what has no single spelling', () => {
  assert.equal(canonical({ b: 1, a: [true, null, 'é'] }), '{"a":[true,null,"é"],"b":1}');
  for (const v of [1.5, -0, 2 ** 53, { A: 1 }, '\ud800', new Date(0)]) assert.equal(code(() => canonical(v)), 'non_canonical');
});

test('a sealed document opens under its key and under no other', () => {
  const k = generateKey(), other = generateKey(), now = Date.now();
  const doc = seal('act', { act_id: 'a', admission_id: 'adm', subject: 's', audience: 'x', scope: 'post.create', body_sha256: '0'.repeat(64), issued_at: now, expires_at: now + 1000 }, k);
  assert.equal(open(doc, k.public_key, 'act').payload, doc.payload);
  assert.equal(code(() => open(doc, other.public_key)), 'unknown_key');
  assert.equal(code(() => open(doc, k.public_key, 'grant')), 'wrong_type');
  assert.equal(code(() => open({ ...doc, key_id: other.key_id }, other.public_key)), 'bad_signature');
});

test('sign in with eID completes, and refuses a forged state', async t => {
  const client = { clientId: 'test-site', clientSecret: 'test-secret-value', redirectUri: 'http://localhost:4499/callback' };
  const other = { clientId: 'other-site', clientSecret: 'other-secret-val', redirectUri: 'http://localhost:4497/callback' };
  const { issuer, server } = await startDevIssuer(4498, [client, other]);
  t.after(() => server.close());
  const rp = new SignIn({ issuer, ...client });
  const follow = async (url: string) => (await fetch(url, { redirect: 'manual' })).headers.get('location')!;

  const a = await rp.start();
  const claims = await rp.finish(await follow(a.url), a.pending);
  assert.equal(claims.eid_ai, true);
  assert.match(claims.sub, /^pw_/);

  const b = await rp.start();
  const back = await follow(b.url);
  await assert.rejects(rp.finish(back, { ...b.pending, state: 'forged' }), /state/);
  // The code was never spent by the refused finish, so the genuine one still completes exactly once.
  assert.equal((await rp.finish(back, b.pending)).sub, claims.sub);
  await assert.rejects(rp.finish(back, b.pending), /token endpoint/);

  // Another site sees a different, equally stable id for the same agent.
  const rp2 = new SignIn({ issuer, ...other });
  const c = await rp2.start();
  const there = await rp2.finish(await follow(c.url), c.pending);
  assert.notEqual(there.sub, claims.sub);
  const d = await rp2.start();
  assert.equal((await rp2.finish(await follow(d.url), d.pending)).sub, there.sub);
});

test('the CLI verifies an act offline and exits by its result', () => {
  const v = vectors.acts.find((c: { name: string }) => c.name === 'valid').input;
  const dir = new URL('../../', import.meta.url);
  const tmp = (name: string, value: unknown) => { const p = new URL(`./.tmp-${name}.json`, dir); writeTemp(p, value); return p.pathname.replace(/^\/([A-Za-z]:)/, '$1'); };
  const args = ['ts/bin/eid.ts', 'verify-act', '--issuer', tmp('issuer', v.issuer), '--anchor', v.trust.anchors[0], '--issuer-id', v.trust.issuer,
    '--admission', tmp('admission', v.admission), '--grant', tmp('grant', v.grant), '--act', tmp('act', v.act), '--audience', v.audience, '--now', String(v.now)];
  const ok = spawnSync(process.execPath, args, { cwd: dir, encoding: 'utf8' });
  assert.equal(ok.stdout.trim(), 'valid'); assert.equal(ok.status, 0);
  const late = spawnSync(process.execPath, [...args.slice(0, -1), String(v.now + 3600_000)], { cwd: dir, encoding: 'utf8' });
  assert.match(late.stdout, /^expired/); assert.equal(late.status, 1);
});

const written: URL[] = [];
function writeTemp(p: URL, value: unknown) { writeFileSync(p, JSON.stringify(value)); written.push(p); }
process.on('exit', () => { for (const p of written) try { unlinkSync(p); } catch { /* gone */ } });
