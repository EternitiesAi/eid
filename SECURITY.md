# Security

eID is a **v1 draft and an unaudited reference implementation**. No independent security review has happened
yet. Do not rely on it alone to protect anything valuable.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's security advisories for this repository
("Report a vulnerability" under the Security tab), not in a public issue. Include the affected file or spec
section, what an attacker can do, and the smallest input that shows it.

We will acknowledge a report within three working days and tell you what we plan to do. When a fix ships, we
credit the reporter unless they ask us not to.

## In scope

- the specification (`spec/`): any way two conforming implementations can disagree about what was signed or
  what a check returns, any way to make a verifier return `valid` when it should not;
- the reference SDKs (`ts/`, `go/`) and the conformance vectors.

The development issuer in `examples/sign-in/` is a toy for localhost and is out of scope, except where its code
could mislead someone copying it.
