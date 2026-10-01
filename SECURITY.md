# Security Policy

## Supported versions

porthole is in early development (0.x). Security fixes are made for the **latest release** only and, until the first
release, for the `main` branch. Please reproduce the issue on the latest release or on `main` before reporting.

| Version | Supported |
|---|---|
| Latest 0.x release | Yes |
| Older releases | No |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull requests.**

Use GitHub Private Vulnerability Reporting instead: open the
[Security tab](https://github.com/eto-a/porthole/security) of the repository, choose **Report a vulnerability**,
and fill in the form. Only the maintainers can see the report, and we can collaborate with you on a fix and an
advisory in a private space.

Please include, as far as you can:

- the affected component (`portholed`, `porthole`, or the protocol in [docs/protocol.md](docs/protocol.md)) and
  version or commit;
- a description of the issue and its impact;
- steps to reproduce, a proof of concept or a failing test;
- any suggested fix or mitigation.

Please do not include real tokens or private keys in a report.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment (accepted, needs more information, or not a vulnerability) shortly after, and regular
  updates while we work on a fix.
- **Our target is to fix confirmed vulnerabilities within 90 days** of the report, and sooner for severe issues.
  We ask you to keep the details private until a fix is released or the 90 days have passed, whichever comes first;
  if a fix needs more time we will tell you why and agree on a date with you.
- Fixes are released together with a GitHub Security Advisory (and a CVE where appropriate). We credit reporters
  unless they prefer to stay anonymous.

## Scope

In scope:

- `portholed`, the server (control endpoint, HTTP and TCP listeners, token handling, storage);
- `porthole`, the client;
- the wire protocol and its implementation (`internal/proto`, `internal/transport`);
- the release artifacts, build and deployment files in this repository (GitHub Actions workflows, `deploy/`).

Examples of issues we want to hear about: authentication or authorization bypass (including token revocation and
expiry not taking effect), one client taking over another client's names or ports, the server being made to connect
to arbitrary addresses, memory or goroutine exhaustion from a small amount of input, request smuggling or header
injection in the HTTP path, secrets leaking into logs.

Out of scope:

- vulnerabilities in third-party software you put in front of or next to porthole (reverse proxies such as Caddy or
  nginx, the operating system, the services you expose through tunnels), unless porthole makes them exploitable in a
  way they otherwise would not be;
- denial of service by sheer traffic volume (bandwidth or connection floods that any server would suffer);
- findings that require an already-compromised server host or a token the attacker legitimately holds, unless they
  go beyond what that token is allowed to do;
- missing hardening in a deployment you configured yourself (for example exposing the server without TLS);
- vulnerabilities in dependencies that are not reachable from porthole (please report those upstream).

## Safe harbor

We consider good-faith security research that follows this policy to be authorized. We will not pursue or support
legal action against you for it, provided that you:

- make a good-faith effort to avoid privacy violations, data destruction and service degradation;
- test only against your own installations, never against other people's servers or tunnels;
- give us a reasonable chance to fix the issue before you disclose it.

If in doubt about whether something is in scope, ask first through the private reporting channel above.
