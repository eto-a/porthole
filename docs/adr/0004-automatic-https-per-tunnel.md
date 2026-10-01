# 0004. Automatic HTTPS for every tunnel host

- Status: accepted
- Date: 2026-10-01
- Issues: #16 (supersedes its DNS-01 plan)

## Context

v0.1 serves TLS from certificate files, typically a wildcard `*.tun.example.com` from certbot with DNS-01. That ties
the install to a DNS provider API and to an external renewal job, and behind a proxy (the live test on Dokploy) tunnel
hosts ended up on plain `http://` because Traefik cannot issue a wildcard without DNS-01.

Decision agreed with the user: every HTTP tunnel gets HTTPS automatically, with no DNS provider integration and no
custom per-tunnel domains.

## Decision

- `portholed` obtains and renews certificates itself via ACME (Let's Encrypt by default) using `certmagic`
  (Apache-2.0, the library behind Caddy), one certificate per host name, issued on demand at the first TLS handshake
  for that name (Caddy `on_demand_tls`). Challenges: TLS-ALPN-01 on the HTTPS listener and HTTP-01 on a new plain
  HTTP listener (`http_listen`, default `:80`), which also redirects every other request to `https://`.
- Abuse guard (Caddy's `ask` endpoint, done in-process): a certificate is requested only for the control host
  `<domain>` and for `<label>.<domain>` where `label` belongs to a live tunnel or a reserved name. Unknown names fail
  the handshake without contacting the CA. Issuance is rate limited per name, and failures back off (certmagic).
- Certificates and the ACME account live in `<data_dir>/certs`. Settings: `tls.acme.email` (optional),
  `tls.acme.ca` (directory URL; the Let's Encrypt staging URL for tests).
- Modes, chosen by configuration: `acme` (the default when no certificate files are set), `files` (v0.1 behaviour, for
  people who already have a wildcard), `off` (plain HTTP behind a proxy that terminates TLS itself).
- Behind a proxy that owns 443 (Dokploy/Traefik): the proxy passes TLS through by SNI (Traefik TCP router with
  `HostSNI(tun.example.com)` and `HostSNIRegexp` for `*.tun.example.com`, `tls.passthrough=true`) to `portholed`'s
  HTTPS listener, and routes HTTP for those hosts to `http_listen`. A ready compose file with these labels is shipped
  in `deploy/`.

## Consequences

- Zero DNS work beyond the wildcard A record; works with any registrar.
- The first request to a new tunnel name waits for issuance (seconds). Names are stable (`blog-home`), so this happens
  once per name and then every 60–90 days in the background.
- Every tunnel host name appears in Certificate Transparency logs. Accepted: the names are not secrets, and private
  access is the SSH gateway's job.
- Let's Encrypt limits (50 certificates per registered domain per week) bound how many new names a server can get
  per week; reusing names costs nothing. Documented, with the staging CA for testing.
- New dependency: `github.com/caddyserver/certmagic`.
