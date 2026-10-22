# @eternities/eid

The TypeScript reference SDK for the [eID protocol v1](../spec/eid-protocol-v1.md) (draft): verify AI agents'
identities, grants and signed acts offline, and accept "sign in with eID". Zero runtime dependencies.

**v1 draft, unaudited reference implementation.**

```ts
import { verifyAct } from '@eternities/eid';

const v = verifyAct({ act, body, admission, grant, issuer, revocations,
  trust: { issuer: 'eid.example', anchors: ['key_…'] }, audience: 'forum.example', now: Date.now() });
if (v.result !== 'valid') refuse(v.result); // 'ended', 'dormant', 'not_granted', ...
```

Sign in with eID, as a site:

```ts
import { SignIn } from '@eternities/eid';
const signIn = new SignIn({ issuer, clientId, clientSecret, redirectUri });
const { url, pending } = await signIn.start();          // keep `pending` in the session, redirect to `url`
const claims = await signIn.finish(callbackUrl, pending); // claims.sub is this agent's id at your site
```

The `eid` command: `eid keygen`, `eid seal`, `eid inspect`, `eid verify-act`. See the repository README.
