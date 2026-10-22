// Sign in with eID, on one machine, in one command:
//
//   node examples/sign-in/demo.ts             open http://localhost:4400 and press "Sign in with eID"
//   node examples/sign-in/demo.ts --headless  run the whole flow without a browser, print the result, exit
//
// Two local servers start: a development issuer (dev-issuer.ts) and a small site that accepts eID. The
// site's whole integration is the SignIn class: start() before the redirect, finish() on the callback.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { SignIn, type PendingSignIn } from '../../ts/src/rp.ts';
import { startDevIssuer } from './dev-issuer.ts';

const SITE = 4400, ISSUER = 4401;
const client = { clientId: 'demo-site', clientSecret: randomBytes(16).toString('base64url'), redirectUri: `http://localhost:${SITE}/callback` };
const { issuer, server: issuerServer } = await startDevIssuer(ISSUER, [client]);
const signIn = new SignIn({ issuer, ...client });

const sessions = new Map<string, PendingSignIn>();
const page = (body: string) => `<!doctype html><meta charset="utf-8"><title>eID demo site</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1d1d1f}a.btn{display:inline-block;padding:.6rem 1rem;border-radius:.5rem;background:#1d1d1f;color:#fff;text-decoration:none}code{background:#f2f2f2;padding:.1rem .3rem;border-radius:.25rem}</style>${body}`;

const site = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${SITE}`);
  const sid = /(?:^|;\s*)sid=([A-Za-z0-9_-]+)/.exec(req.headers.cookie ?? '')?.[1];
  try {
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(page(`<h1>A site that accepts eID</h1><p>Agents sign in here as themselves: no password, and no pretending to be a person.</p><p><a class="btn" href="/login">Sign in with eID</a></p>`));
    }
    if (url.pathname === '/login') {
      const { url: to, pending } = await signIn.start();
      const id = randomBytes(18).toString('base64url');
      sessions.set(id, pending);
      res.writeHead(302, { location: to, 'set-cookie': `sid=${id}; HttpOnly; SameSite=Lax; Path=/` });
      return res.end();
    }
    if (url.pathname === '/callback') {
      const pending = sid ? sessions.get(sid) : undefined;
      if (sid) sessions.delete(sid);
      if (!pending) throw new Error('no sign-in in progress');
      const claims = await signIn.finish(url.toString(), pending);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(page(`<h1>Signed in</h1><p>An AI agent signed in with eID.</p><p>Its id at this site: <code>${claims.sub}</code><br>Issuer: <code>${claims.iss}</code><br>Disclosed as an AI agent: <code>${claims.eid_ai}</code></p><p>Another site would see a different id for the same agent.</p>`));
    }
    res.writeHead(404); res.end();
  } catch (e) {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }); res.end(`sign-in refused: ${(e as Error).message}`);
  }
});
await new Promise<void>(r => site.listen(SITE, '127.0.0.1', r));

if (process.argv.includes('--headless')) {
  // An agent's runtime follows the redirects itself, holding the site's cookie, with no browser.
  let cookie = '', at = `http://localhost:${SITE}/login`, html = '';
  for (let hops = 0; hops < 5; hops++) {
    const res = await fetch(at, { redirect: 'manual', headers: cookie ? { cookie } : {} });
    const set = res.headers.get('set-cookie'); if (set) cookie = set.split(';')[0];
    if (res.status === 302) { at = new URL(res.headers.get('location')!, at).toString(); continue; }
    html = await res.text(); break;
  }
  const sub = /<code>(pw_[A-Za-z0-9_-]+)<\/code>/.exec(html)?.[1];
  console.log(sub ? `signed in: ${sub} (disclosed as an AI agent)` : `failed: ${html.slice(0, 200)}`);
  site.close(); issuerServer.close();
  process.exit(sub ? 0 : 1);
} else {
  console.log(`eID demo site:   http://localhost:${SITE}\ndev issuer:      ${issuer}\npress ctrl+c to stop`);
}
