// Thirty seconds of eID: an issuer admits an agent, grants it one scope at one site, the agent signs an
// act with its own key, and the site verifies it offline. Then three things that must fail, do.
//   node examples/quickstart.ts
import { generateKey, seal, verifyAct, sha256Hex } from '../ts/src/index.ts';

const now = Date.now(), min = 60_000, day = 86_400_000;
const issuerKey = generateKey();   // the issuer's signing key
const agentKey = generateKey();    // the agent's own key: the issuer never sees its seed

const issuer = seal('issuer', { issuer: 'eid.example', keys: [{ key_id: issuerKey.key_id, public_key: issuerKey.public_key, not_before: now - min, not_after: now + 365 * day }], issued_at: now - min, expires_at: now + 30 * day }, issuerKey);
const admission = seal('admission', { admission_id: 'adm-1', issuer: 'eid.example', subject: 'agent-1', holder_keys: [{ key_id: agentKey.key_id, public_key: agentKey.public_key }], disclosed_ai: true, issued_at: now - min, expires_at: now + 29 * day }, issuerKey);
const grant = seal('grant', { grant_id: 'grant-1', issuer: 'eid.example', admission_id: 'adm-1', subject: 'agent-1', audience: 'forum.example', scopes: ['post.create'], issued_at: now - min, expires_at: now + day }, issuerKey);

const body = JSON.stringify({ title: 'hello', text: 'my first post, signed by me' });
const act = seal('act', { act_id: 'act-1', admission_id: 'adm-1', subject: 'agent-1', audience: 'forum.example', scope: 'post.create', body_sha256: sha256Hex(body), issued_at: now, expires_at: now + min }, agentKey);

// The site pinned the issuer's key id ahead of time. Everything below runs with no network.
const check = (label: string, over: object = {}) => {
  const v = verifyAct({ act, body, admission, grant, issuer, trust: { issuer: 'eid.example', anchors: [issuerKey.key_id] }, audience: 'forum.example', now, ...over });
  console.log(`${label.padEnd(34)} ${v.result}`);
};
check('the agent posts');
check('someone edits the post', { body: body.replace('hello', 'goodbye') });
check('the act is replayed elsewhere', { audience: 'shop.example' });
check('the issuer revoked the admission', { revocations: [seal('revocation', { revocation_id: 'rev-1', issuer: 'eid.example', target_kind: 'admission', target_id: 'adm-1', reason: 'policy', issued_at: now - 1 }, issuerKey)] });
