// A development issuer for trying "sign in with eID" on one machine. It is a toy: it holds its key in
// memory, keeps codes in a Map, and signs in one demonstration agent without asking it anything. A real
// eID issuer authenticates the agent itself (with the agent's own key) and checks that the agent's owner
// granted sign-in to exactly this site. Never run this anywhere but localhost.
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { generateKey } from '../../ts/src/keys.ts';
import { signIdToken, jwksOf } from '../../ts/src/signin.ts';

export interface DevClient { clientId: string; clientSecret: string; redirectUri: string }

export function startDevIssuer(port: number, clients: DevClient[]): Promise<{ issuer: string; server: Server }> {
  const key = generateKey();
  const pairwiseSecret = randomBytes(32);
  const issuer = `http://localhost:${port}`;
  const now = Date.now();
  const doc = { issuer, keys: [{ key_id: key.key_id, public_key: key.public_key, not_before: now - 60_000, not_after: now + 86_400_000 }], issued_at: now, expires_at: now + 86_400_000 };
  const codes = new Map<string, { clientId: string; redirectUri: string; challenge: string; nonce: string; sub: string; until: number }>();
  // Pairwise subject: the same agent gets a different, stable id at every site.
  const pairwise = (agent: string, clientId: string) => 'pw_' + createHmac('sha256', pairwiseSecret).update(agent + '\n' + clientId).digest('base64url').slice(0, 32);

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', issuer);
    const send = (status: number, body: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }); res.end(JSON.stringify(body));
    };
    if (url.pathname === '/.well-known/openid-configuration') return send(200, {
      issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/jwks',
      response_types_supported: ['code'], subject_types_supported: ['pairwise'], id_token_signing_alg_values_supported: ['EdDSA'],
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['client_secret_basic'], claims_supported: ['iss', 'sub', 'aud', 'iat', 'exp', 'nonce', 'eid_ai'],
    });
    if (url.pathname === '/jwks') return send(200, jwksOf(doc, Date.now()));
    if (url.pathname === '/authorize') {
      const q = url.searchParams, client = clients.find(c => c.clientId === q.get('client_id'));
      // Never redirect to an address the site did not register.
      if (!client || q.get('redirect_uri') !== client.redirectUri) return send(400, { error: 'invalid_client' });
      const back = new URL(client.redirectUri);
      if (q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256' || !q.get('code_challenge') || !q.get('nonce') || !q.get('state')) {
        back.search = new URLSearchParams({ error: 'invalid_request', state: q.get('state') ?? '' }).toString();
      } else {
        const code = randomBytes(24).toString('base64url');
        codes.set(code, { clientId: client.clientId, redirectUri: client.redirectUri, challenge: q.get('code_challenge')!, nonce: q.get('nonce')!, sub: pairwise('demo-agent', client.clientId), until: Date.now() + 60_000 });
        back.search = new URLSearchParams({ code, state: q.get('state')! }).toString();
      }
      res.writeHead(302, { location: back.toString(), 'cache-control': 'no-store' }); return res.end();
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      let body = ''; for await (const chunk of req) body += chunk;
      const form = new URLSearchParams(body);
      const [id, secret] = Buffer.from((req.headers.authorization ?? '').replace(/^Basic /, ''), 'base64').toString().split(':').map(decodeURIComponent);
      const client = clients.find(c => c.clientId === id && c.clientSecret === secret);
      const entry = codes.get(form.get('code') ?? '');
      codes.delete(form.get('code') ?? ''); // a code is good once
      if (!client || !entry || entry.clientId !== client.clientId || entry.until < Date.now() || form.get('redirect_uri') !== entry.redirectUri ||
        createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url') !== entry.challenge) return send(400, { error: 'invalid_grant' });
      const iat = Math.floor(Date.now() / 1000);
      return send(200, { token_type: 'Bearer', id_token: signIdToken({ iss: issuer, sub: entry.sub, aud: client.clientId, iat, exp: iat + 300, nonce: entry.nonce, eid_ai: true }, key) });
    }
    send(404, { error: 'not_found' });
  });
  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve({ issuer, server })));
}
