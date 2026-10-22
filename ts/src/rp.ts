// The relying-party kit for "sign in with eID": an OpenID Connect authorization code flow with PKCE
// (S256), state and nonce, finishing in verifyIdToken. Uses the platform's fetch; no dependencies.
import { createHash, randomBytes } from 'node:crypto';
import { EidError } from './canonical.ts';
import { verifyIdToken, type IdTokenClaims, type Jwks } from './signin.ts';

export interface SignInConfig {
  /** The issuer identifier, an https URL (http is allowed only for localhost). */
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  fetch?: typeof fetch;
  now?: () => number;
}

/** What the site keeps between start() and finish(), in the visitor's session. Never in the URL. */
export interface PendingSignIn { state: string; nonce: string; verifier: string }

interface Discovery { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string }

const token = () => randomBytes(32).toString('base64url');
const allowedUrl = (u: string) => { const url = new URL(u); return url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)); };

export class SignIn {
  private readonly c: SignInConfig;
  private discovery?: Discovery;
  constructor(config: SignInConfig) {
    if (!allowedUrl(config.issuer)) throw new EidError('invalid_field', 'the issuer is an https URL');
    this.c = config;
  }
  private get f() { return this.c.fetch ?? fetch; }

  private async discover(): Promise<Discovery> {
    if (this.discovery) return this.discovery;
    const res = await this.f(this.c.issuer.replace(/\/$/, '') + '/.well-known/openid-configuration', { redirect: 'error' });
    if (!res.ok) throw new EidError('malformed', `discovery answered ${res.status}`);
    const d = await res.json() as Discovery;
    if (d.issuer !== this.c.issuer) throw new EidError('untrusted_issuer', 'discovery names another issuer');
    for (const u of [d.authorization_endpoint, d.token_endpoint, d.jwks_uri]) if (typeof u !== 'string' || !allowedUrl(u)) throw new EidError('invalid_field', 'discovery endpoint');
    return (this.discovery = d);
  }

  /** Begins a sign-in: where to send the agent, and what to keep until it comes back. */
  async start(): Promise<{ url: string; pending: PendingSignIn }> {
    const d = await this.discover();
    const pending = { state: token(), nonce: token(), verifier: token() };
    const url = new URL(d.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: 'code', client_id: this.c.clientId, redirect_uri: this.c.redirectUri, scope: 'openid',
      state: pending.state, nonce: pending.nonce,
      code_challenge: createHash('sha256').update(pending.verifier).digest('base64url'), code_challenge_method: 'S256',
    }).toString();
    return { url: url.toString(), pending };
  }

  /** Finishes a sign-in from the callback URL the agent arrived at. Returns the verified claims. */
  async finish(callbackUrl: string, pending: PendingSignIn): Promise<IdTokenClaims> {
    const q = new URL(callbackUrl).searchParams;
    if (q.get('error')) throw new EidError('not_granted', `the issuer answered ${q.get('error')}`);
    if (q.get('state') !== pending.state) throw new EidError('mismatch', 'state');
    const code = q.get('code');
    if (!code) throw new EidError('malformed', 'no code');
    const d = await this.discover();
    const res = await this.f(d.token_endpoint, {
      method: 'POST', redirect: 'error',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: 'Basic ' + Buffer.from(`${encodeURIComponent(this.c.clientId)}:${encodeURIComponent(this.c.clientSecret)}`).toString('base64') },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: this.c.redirectUri, code_verifier: pending.verifier }).toString(),
    });
    if (!res.ok) throw new EidError('not_granted', `the token endpoint answered ${res.status}`);
    const body = await res.json() as { id_token?: string };
    if (typeof body.id_token !== 'string') throw new EidError('malformed', 'no id_token');
    const jwksRes = await this.f(d.jwks_uri, { redirect: 'error' });
    if (!jwksRes.ok) throw new EidError('malformed', `jwks answered ${jwksRes.status}`);
    const jwks = await jwksRes.json() as Jwks;
    return verifyIdToken(body.id_token, { jwks, issuer: this.c.issuer, audience: this.c.clientId, nonce: pending.nonce, now: (this.c.now ?? Date.now)() });
  }
}
