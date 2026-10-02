# Server setup (`portholed`)

`portholed` is the server: it terminates the client sessions, routes HTTP tunnels by `Host`, listens on the public ports of TCP tunnels and (optionally) runs the [SSH gateway](ssh.md). You need a machine with a public IP address and a domain you control. The examples use `tun.example.com`.

Install `portholed` first, see [Installation](install.md); the deb and rpm packages also set up the systemd unit and the `porthole` user. Then follow the steps below: DNS, TLS, configuration, firewall, run, create a token. Client setup is in the [Client guide](client.md).

## DNS

Point the domain and a wildcard at the server's IP address:

```
tun.example.com.     A   203.0.113.10
*.tun.example.com.   A   203.0.113.10
```

## TLS

`portholed` has three TLS modes, set with `tls.mode` ([ADR 0004](adr/0004-automatic-https-per-tunnel.md)):

| Mode | When | What it does |
|---|---|---|
| `acme` (default) | no certificate files configured | Obtains and renews a certificate per host name itself, from Let's Encrypt by default. No DNS provider and no external renewal job |
| `files` | `tls.cert_file` and `tls.key_file` set | Serves the certificate you provide, for example a wildcard from certbot |
| `off` | behind a proxy that terminates TLS | Plain HTTP, see [Behind a reverse proxy](#behind-a-reverse-proxy) |

An empty `tls.mode` means `files` when the certificate files are set and `acme` otherwise.

### Automatic certificates (`acme`)

Nothing to configure beyond the DNS records above and reachable ports 443 and 80. The first TLS handshake for a host name triggers issuance (a few seconds, once per name); the certificate is then renewed in the background 30 days before it expires. Challenges: TLS-ALPN-01 on the HTTPS listener and HTTP-01 on the plain HTTP listener (`http_listen`, default `:80`), which also redirects every other request to `https://`. `GET /healthz` is answered on that listener as well. Certificates and the ACME account are stored in `<data_dir>/certs` (keep the directory across restarts; it must be writable by the service user).

A certificate is requested only for the control host `tun.example.com` and for `<label>.tun.example.com` where the label belongs to a live tunnel (or to one whose client disconnected a moment ago). Handshakes for any other name fail without contacting the CA and are logged as `certificate refused` with the host name, so scanners cannot burn your rate limits.

#### Certificate budget

A client that registers a tunnel, opens its host name once and unregisters again could request new certificates in a loop and use up the CA's limit for the whole domain (Let's Encrypt: 50 new certificates per registered domain per week), leaving every other tenant without TLS for days. The server therefore keeps a budget of *new* names: at most `tls.acme.max_new_names_per_client_per_hour` (default 10) per client and `tls.acme.max_new_names_per_day` (default 30) for all clients together. A name is charged when its certificate is first requested (failed requests count too, as they count at the CA); a name that already has a certificate in `<data_dir>/certs` costs nothing, and neither do renewals. Refused requests are logged as `certificate refused: issuance budget`. For a multi-tenant server with many short-lived names, use a wildcard certificate instead (`tls.mode: files`, see below), which has no per-name issuance.

```yaml
tls:
  mode: acme              # the default
  acme:
    email: you@example.com                                    # optional: expiry notices from the CA
    ca: https://acme-v02.api.letsencrypt.org/directory        # default; see staging below
# http_listen: ":80"      # default in acme mode; "" disables the listener (then only TLS-ALPN-01 works)
```

Things to know:

- **Let's Encrypt limits.** 50 certificates per registered domain per week, and 5 duplicates of the same name per week (see [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/)). Every new tunnel name costs one certificate; reusing a name costs nothing, because the certificate is already stored. Choose stable names.
- **Staging.** To test without touching the production limits, set `tls.acme.ca: https://acme-staging-v02.api.letsencrypt.org/directory`. Staging certificates are not trusted by browsers; switch back and clear `<data_dir>/certs` when you go live.
- **Certificate Transparency.** Every issued name is published in public CT logs. Tunnel host names are therefore not secret; protect private services with the [SSH gateway](ssh.md) or authentication in the application.
- **Ports.** The CA connects to port 443 and 80 of the domain from the internet. Behind a proxy that owns those ports use TLS passthrough, see [Behind Traefik or Dokploy](#behind-traefik-or-dokploy-tls-passthrough).

### Your own certificate (`files`)

If you already have a wildcard certificate (a wildcard does not cover the apex, so it must list both `tun.example.com` and `*.tun.example.com`), point to it. With certbot and a DNS-01 plugin, for example Cloudflare:

```console
$ certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
    -d tun.example.com -d '*.tun.example.com'
```

```yaml
tls:
  cert_file: /etc/porthole/tls/fullchain.pem
  key_file: /etc/porthole/tls/privkey.pem
```

Certificates are read from files and a renewed one is picked up without a restart: within a minute, or immediately after `systemctl reload portholed` (SIGHUP), which is what your renewal hook should run. `http_listen` is off in this mode; set it (for example `":80"`) to get the `https://` redirect.

## Configuration

The file is `/etc/porthole/portholed.yaml` (override with `--config`); the full annotated example is [deploy/portholed.example.yaml](../deploy/portholed.example.yaml). A minimal one:

```yaml
version: 1
domain: tun.example.com
listen: ":443"
tcp_port_range: "20000-29999"
data_dir: /var/lib/porthole
```

With no `tls` section the server gets its certificates by ACME (see [TLS](#tls)). Unknown keys are rejected. Most settings can also be given as a `PORTHOLED_*` environment variable, which overrides the file, for example `PORTHOLED_DOMAIN` or `PORTHOLED_TCP_PORT_RANGE`; the table below names each one. Settings marked `-` in the Environment column (`version`, `shutdown_grace`, `ssh_gateway.max_conns_per_tunnel`, `tls.acme.max_new_names_*` and every `limits.*` key) exist only in the file. Pass `--config ""` to configure the server only through the environment.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `version` | - | required (`1`) | Configuration schema version |
| `domain` | `PORTHOLED_DOMAIN` | required | Base domain, a bare host name (no scheme or port) |
| `listen` | `PORTHOLED_LISTEN` | `:443` | HTTP(S) listener: control endpoint, health check and HTTP tunnels |
| `tls.mode` | `PORTHOLED_TLS_MODE` | `files` if certificate files are set, else `acme` | `acme`, `files` or `off` (plain HTTP behind a TLS-terminating proxy) |
| `tls.cert_file`, `tls.key_file` | `PORTHOLED_TLS_CERT_FILE`, `PORTHOLED_TLS_KEY_FILE` | unset | PEM certificate and key for mode `files`; set both or neither |
| `tls.acme.email` | `PORTHOLED_ACME_EMAIL` | unset | Optional ACME account contact address (mode `acme`) |
| `tls.acme.ca` | `PORTHOLED_ACME_CA` | Let's Encrypt production | ACME directory URL (mode `acme`); the staging URL is in [TLS](#tls) |
| `http_listen` | `PORTHOLED_HTTP_LISTEN` | `:80` in mode `acme`, off otherwise | Plain HTTP listener for ACME HTTP-01 and the `https://` redirect; empty disables it; not allowed in mode `off` |
| `public_scheme`, `public_port` | `PORTHOLED_PUBLIC_SCHEME`, `PORTHOLED_PUBLIC_PORT` | `https`, no port | Scheme and port in the public HTTP tunnel URLs shown to clients; change only for local development or when the public port differs from the listening port |
| `server_url` | `PORTHOLED_SERVER_URL` | derived from `public_scheme`, `domain` and `public_port` | Address clients connect to, as printed in `porthole login <server_url> <token>` and in join links; set it when the control endpoint is reached differently from the tunnel hosts (for example HTTPS at a proxy while the tunnels are plain HTTP). Absolute `http(s)` URL without a path |
| `tcp_port_range` | `PORTHOLED_TCP_PORT_RANGE` | `20000-29999` | Inclusive range of public ports for TCP (and `--public-port` SSH) tunnels |
| `tcp_bind_host` | `PORTHOLED_TCP_BIND_HOST` | all interfaces | Address the TCP tunnel listeners bind to |
| `data_dir` | `PORTHOLED_DATA_DIR` | `/var/lib/porthole` | Directory of the SQLite database (`porthole.db`: tokens and port reservations) and, in mode `acme`, of `certs/`; must be writable by the service user |
| `admin_socket` | `PORTHOLED_ADMIN_SOCKET` | `<data_dir>/admin.sock` | Unix socket of the admin API used by `portholed join`, `admin` and `mcp` (mode `0600`: whoever can open it is a full administrator); `-` turns it off. Not served on Windows |
| `ssh_gateway.listen` | `PORTHOLED_SSH_LISTEN` | off | Address of the SSH gateway, for example `:2222` (see [SSH gateway](#ssh-gateway)) |
| `ssh_gateway.max_conns_per_tunnel` | - | `256` | Concurrent SSH channels per tunnel |
| `metrics_listen` | `PORTHOLED_METRICS_LISTEN` | off | Address of the metrics and profiling listener, for example `127.0.0.1:9090` (see [Metrics](#metrics)) |
| `trust_proxy_headers` | `PORTHOLED_TRUST_PROXY_HEADERS` | `false` | Take visitor IP addresses from `X-Forwarded-For`, read from the right: the right-most address that is not in `trusted_proxies` (with an empty `trusted_proxies`: the right-most address). With `trusted_proxies` set, the header is honoured only from peers in that list (see [Behind a reverse proxy](#behind-a-reverse-proxy)) |
| `proxy_protocol` | `PORTHOLED_PROXY_PROTOCOL` | `false` | Accept PROXY protocol v1/v2 headers on the HTTPS listener (the SSH gateway only with `proxy_protocol_ssh`), from the peers in `trusted_proxies` only (see [Behind Traefik or Dokploy](#behind-traefik-or-dokploy-tls-passthrough)) |
| `proxy_protocol_ssh` | `PORTHOLED_PROXY_PROTOCOL_SSH` | `false` | Also accept it on the SSH gateway (`ssh_gateway.listen`); needs `proxy_protocol` |
| `proxy_protocol_http` | `PORTHOLED_PROXY_PROTOCOL_HTTP` | `false` | Also accept it on the plain HTTP listener (`http_listen`); needs `proxy_protocol` |
| `trusted_proxies` | `PORTHOLED_TRUSTED_PROXIES` (comma-separated) | empty | IP addresses and CIDR ranges of the proxies allowed to send PROXY headers (required by `proxy_protocol`) and whose `X-Forwarded-For` is believed when `trust_proxy_headers` is on |
| `max_tunnels_per_client` | `PORTHOLED_MAX_TUNNELS_PER_CLIENT` | `10` | Simultaneous tunnels for tokens without a limit of their own |
| `traffic.max_requests`, `traffic.max_conns` | `PORTHOLED_TRAFFIC_MAX_REQUESTS`, `PORTHOLED_TRAFFIC_MAX_CONNS` | `10000` each | Size of the in-memory request log and connection log; `0` turns a log off. Lost on restart (see [Request log and inspection](#request-log-and-inspection)) |
| `traffic.allow_inspect` | `PORTHOLED_TRAFFIC_ALLOW_INSPECT` | `true` | Let clients ask for body inspection of an HTTP tunnel (`porthole http --inspect`); with `false` such a tunnel is refused |
| `traffic.max_detail_bytes` | `PORTHOLED_TRAFFIC_MAX_DETAIL_BYTES` | `67108864` (64 MiB) | Memory for stored headers and bodies of inspected requests; when exceeded the oldest details are dropped (the log entries stay). `0` stores no details |
| `audit.max_rows` | `PORTHOLED_AUDIT_MAX_ROWS` | `100000` | Newest rows of the admin audit log kept in the database; older rows are deleted (see [Audit log](#audit-log)) |
| `shutdown_grace` | - | `10s` | How long graceful shutdown (SIGINT/SIGTERM) may take before connections are cut |
| `tls.acme.max_new_names_per_day` | - | `30` | Host names without a stored certificate that the server requests per 24 hours, all clients together; `-1` turns the cap off (see [Certificate budget](#certificate-budget)) |
| `tls.acme.max_new_names_per_client_per_hour` | - | `10` | The same cap for the tunnels of one client per hour; `-1` turns it off |
| `limits.max_conns_per_ip` | - | `32` | Simultaneous connections from one source IP (IPv6: one /64) to the TCP tunnels and, separately, to the SSH gateway; `-1` turns the limit off |
| `limits.tcp_idle_timeout` | - | `2h` | A TCP or SSH connection through a tunnel with no bytes in either direction for this long is closed; `-1` turns it off (the half-close limit below stays) |
| `limits.tcp_half_close_timeout` | - | `5m` | A TCP or SSH connection that one side has half-closed and that carried no bytes since is closed after this long, independently of `limits.tcp_idle_timeout`; `-1` turns it off |
| `limits.max_http_requests_per_tunnel` | - | `512` | Simultaneous visitor requests (open WebSockets included) per HTTP tunnel; more get `503`; `-1` turns the limit off |
| `limits.http_body_idle_timeout` | - | `60s` | A visitor request whose body makes no progress for this long is aborted with `408`; steady slow uploads are not affected; `-1` turns it off |
| `limits.max_pending_handshakes`, `limits.max_pending_handshakes_per_ip` | - | `256`, `8` | Control connections that have not authenticated yet, overall and per source IP; more get `503` (see [Abuse limits](#abuse-limits)) |
| `limits.max_label_claims_per_client`, `limits.label_claim_ttl` | - | `4 x max_tunnels_per_client` (at least `40`), `720h` | Permanent host names one client may hold, and how long an unused one is kept (see [Host names](#host-names-are-per-client-tunnel)) |

## Firewall

Open TCP 443 (control connections and HTTP tunnels), TCP 80 in mode `acme` (HTTP-01 challenge and redirect), the TCP port range for TCP tunnels, and the SSH gateway port (for example 2222) if you enable it.

## Run it

With the deb or rpm package the unit and the `porthole` user already exist and the example configuration is installed as `/etc/porthole/portholed.yaml` (only if missing; upgrades never touch it, and the current example is in `/usr/share/porthole/portholed.example.yaml`): edit it as above, then

```console
$ sudo systemctl enable --now portholed
$ sudo systemctl status portholed
```

Without a package, run it by hand (or install the unit [deploy/portholed.service](../deploy/portholed.service) yourself, see the comments in it) or use a container image (see [Docker](#docker)):

```console
$ portholed serve --config /etc/porthole/portholed.yaml
```

`portholed serve` takes `--log-level` (`debug`, `info`, `warn` or `error`; default `info`).

## Join links

The recommended way to give a machine access is a one-time join link: nobody copies a long-lived secret around. The command needs the running server (it talks to the local admin unix socket, `admin_socket` in the configuration), so run it as the user the service runs as:

```console
$ sudo -u porthole portholed join create --name home
Join link for "home" (id 3kq9w2m1z8xa), valid until 2026-10-01 12:15 UTC and usable once.

On the machine, run:

    porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...
```

On the machine, `porthole join <link>` redeems the link once and stores the server and its own permanent token (see [Client guide](client.md#join-with-a-link)). The server keeps only a hash of the code. The link works once, expires after 15 minutes by default and cannot be used to create anything but the token it was made for. Opening the link in a browser (`GET /j/<code>`) only shows the command and does not use it up. Redemptions are rate-limited per IP with the same limiter as failed logins and written to the audit log as `join.redeem`.

| Flag of `join create` | Meaning |
|---|---|
| `--name` | Client name, required; becomes part of tunnel URLs. Fails if an active token already has it |
| `--ttl` | Lifetime of the link: `15m` (default) up to `7d` |
| `--scopes` | Scopes of the token the link creates (default `tunnel:http,tunnel:tcp,tunnel:udp`) |
| `--max-tunnels` | Maximum simultaneous tunnels (`0`: the server default) |
| `--expires` | Lifetime of the created token, longer than `--ttl` (default: no expiry) |
| `--no-remote-control` | Do not let operators open tunnels on this machine remotely (the default allows it) |

```console
$ portholed join list             # --all also shows used, revoked and expired links; --json prints the list
$ portholed join revoke 3kq9w2m1z8xa
```

The same operations are in the admin API with a token that has the scope `admin:tokens`: `POST /_porthole/admin/v1/join` (`client_name`, `scopes`, `ttl`, `max_tunnels`, `token_expires_in`, `remote_control`), `GET /_porthole/admin/v1/join` and `POST /_porthole/admin/v1/join/{id}/revoke`. The link uses `server_url` from the configuration, or `<public_scheme>://<domain>[:<public_port>]` when it is not set.

A link made with a bearer token (admin API or MCP) is limited by what that token may do itself; only the local admin socket (`portholed join create`) is exempt:

- no `admin:*` scope can be granted, not even one the token holds: it could mint itself a permanent copy that outlives its revocation;
- `connect:<client>` only if the token holds that scope or is that client;
- `max_tunnels` at most `max_tunnels_per_client` (a larger value is refused);
- neither the link nor the minted token outlives the creating token: `token_expires_in` is capped at the creator's expiry (the response shows `token_expires_at`), and a token that expires within the minimum link lifetime cannot create links at all. A creator without expiry may mint tokens without expiry.

Revoking a token also revokes the join links it created and nobody has used yet. Tokens made from a link remember their creator (`created_by`, shown by `portholed token list`); `portholed token revoke --cascade <id>` revokes those tokens too, transitively.

The join page `/j/<code>` carries the secret in the URL path, so it ends up in the access logs of a reverse proxy (nginx, Caddy `log`); anyone who can read those logs can redeem the link within its lifetime (15 minutes by default). Keep link lifetimes short and exclude `/j/` from proxy access logs, or hand out only the `porthole join` command.

## Tokens

`portholed token create` is the alternative for scripted setups and for machines that cannot reach the server over HTTP(S) at enrolment time. Create one token per client machine; the name becomes the client name in the public URLs:

```console
$ sudo -u porthole portholed token create --name home
```

The token is shown once (the server stores only a hash), together with a ready-to-use `porthole login` command. The `token` commands read the same configuration and database as `serve` (use `--config` if it is not at `/etc/porthole/portholed.yaml`) and work while the server is running. Run them as the user the service runs as (`sudo -u porthole` above): a database created by root cannot be opened by the service. Under Docker, use `docker exec` as shown in [Installation](install.md#docker). Token names are 1-32 characters of `a-z`, `0-9` and `-`. More options (without the `sudo -u porthole` prefix):

```console
$ portholed token create --name office-nas --expires 30d --scopes tunnel:http,tunnel:tcp --max-tunnels 5
$ portholed token list            # --all includes revoked tokens, --json prints a JSON array
$ portholed token revoke home     # by id or name; takes effect on live sessions (see below)
$ portholed token revoke --cascade agent   # also the tokens made from the join links of "agent"
```

`token create` and `token revoke` work on the database directly and are written to the audit log with the actor `cli` (and the operating system user in the arguments). A revoke through the admin API or the MCP tool closes the token's live sessions at once; the CLI runs in another process, so the server notices within 30 seconds. A token that has only `admin:*` and `connect:*` scopes and no `tunnel:*` scope cannot open a client session (the handshake is refused with `forbidden`): it is for the admin API or the SSH gateway.

### Audit log

The admin audit log lives in the database. `audit.max_rows` (`PORTHOLED_AUDIT_MAX_ROWS`, default `100000`) keeps only the newest rows. Of a flood of refused (`denied`) calls from one token only the first per minute is stored; the next row says in `args.suppressed` how many were dropped. Page through it with `GET /_porthole/admin/v1/audit?limit=100&before=<id>` (entries with an id below `before`, newest first). MCP calls over HTTP record the caller's address as `remote`.

| Flag of `token create` | Meaning |
|---|---|
| `--name` | Client name, required; becomes part of tunnel URLs |
| `--expires` | Lifetime: `30d`, `720h` or `0` for no expiry (default `0`) |
| `--scopes` | Comma-separated scopes (default `tunnel:http,tunnel:tcp,tunnel:udp`) |
| `--max-tunnels` | Maximum simultaneous tunnels (`0`: the server default `max_tunnels_per_client`) |
| `--no-remote-control` | Do not let operators open tunnels on this machine remotely (by default they may) |

A token is a client identity: every client sees and manages only its own tunnels and names. Tokens are 256-bit secrets stored only as hashes; authorization is re-checked on every tunnel registration and revocation applies to live sessions. A token of one client can also be given the scope `connect:<client>`, which lets its holder pass the [private SSH gateway](ssh.md#public-and-private-machines) of that client without owning it. `portholed token revoke` also deletes the client's [port reservations](#tcp-ports-and-reservations).

## TCP ports and reservations

TCP tunnels (and SSH tunnels in `--public-port` mode) get a port from `tcp_port_range`; `porthole tcp 5432 --remote-port 20017` asks for a specific one. The port is reserved for the pair (client, tunnel name): when the tunnel goes away, the reservation is kept for 24 hours, so a reconnecting client gets the same address. Reservations are stored in the SQLite database, so they survive a server restart or crash (the 24 hours then start at the restart). A changed `tcp_port_range` ignores reservations outside the new range. See [ADR 0003](adr/0003-ssh-gateway-and-port-reservations.md).

## Abuse limits

Everything below applies per source IP (IPv6 addresses are grouped by /64, the smallest block one customer holds), and all numbers are configurable (see the `limits.*` rows of the [Configuration](#configuration) table).

- **Failed authentication.** Wrong tokens and join codes, and control connections that stay silent or send garbage until the handshake timeout, use up a budget of 10 failures per source plus 5 per minute. The budgets are separate per surface: control handshakes, the admin API and MCP, join links, and the SSH gateway. Failures on one surface do not lock a client out of another. The table is bounded; when it is full, the entry with the most recovered budget is dropped, so a new source is always tracked and the limiter never switches off. Behind a proxy that does not pass the visitor address on (see [Behind a reverse proxy](#behind-a-reverse-proxy)), all visitors share one source.
- **Unauthenticated control connections.** At most `limits.max_pending_handshakes_per_ip` (8) per source and `limits.max_pending_handshakes` (256) overall may be waiting for their `hello`; the rest get `503`. Until the token is accepted a connection may send at most 128 KiB; beyond that it is closed.
- **TCP tunnels and the SSH gateway.** `limits.max_conns_per_ip` (32) simultaneous connections per source, counted separately for TCP tunnels and for the gateway, on top of the per-tunnel limits (1024 TCP connections, `ssh_gateway.max_conns_per_tunnel`). Raise it if many users reach a tunnel through one NAT.
- **Idle connections.** TCP and SSH connections through a tunnel are closed after `limits.tcp_idle_timeout` (2h) without traffic in either direction, and after `limits.tcp_half_close_timeout` (5 minutes) of silence once one side has half-closed, also when the idle limit is off. WebSocket connections to HTTP tunnels are not subject to it; their applications are expected to send keepalives.
- **HTTP tunnels.** `limits.max_http_requests_per_tunnel` (512) simultaneous requests; a request body that stalls for `limits.http_body_idle_timeout` (60s) is aborted with `408`. The timeout applies between reads of the body, so slow but steady uploads and long streaming responses are unaffected.

### Host names are per (client, tunnel)

The public name of an HTTP tunnel is `<tunnel>-<client>`, and so is the address of an SSH tunnel on the gateway; both parts may contain hyphens, so different pairs can compose to the same name (client `x-b` with tunnel `a`, client `b` with tunnel `a-x`). The first registration wins and **keeps the name for good**: the store remembers the claim (table `label_claims`), so it survives the client being offline for any time, an `unregister` and a server restart. The second pair is refused with `name_taken`. The claim ends when the owner's token is revoked, or when you release it by hand:

```console
$ portholed admin release-label web-a-home
```

(the admin API does the same with `POST /_porthole/admin/v1/labels/<label>/release`, scope `admin:tunnels`, and the call is audited as `label.release`). While a client is offline for a short time, its HTTP name also answers `502` for two minutes, so visitors see "offline" rather than "not found" during a reconnect.

The gateway resolves a target by the exact name: the bare client name for the client's tunnel called `ssh`, otherwise the exact `<tunnel>-<client>`; it never guesses where the tunnel name ends. The bare names and the `<tunnel>-<client>` names of SSH tunnels are one namespace, so the claims cover both: an `ssh` tunnel of client `a-b` is refused when another client's tunnel already holds `a-b`, and the other way round. For the same reason `portholed token create` and `join create` refuse a client name that is already the claimed name of another client's tunnel.

**A client name is reserved from the moment its token exists**, not from the first `ssh` registration: while the token of client `web-b` is active, no other client can register a tunnel whose HTTP name or SSH address would be `web-b` (client `b` with the tunnel `web`), in either order, so nobody can make `ssh web-b` land on their own machine. The reservation ends when the token is revoked and also covers tokens that were created before this rule existed. A claim of that kind made before the upgrade stays in the table, but its tunnel is refused with `name_taken` on its next registration.

Claims are bounded so that a client cannot hoard names by registering and closing tunnels with ever new names (which would also reserve `*-<client>` for future clients):

- `limits.max_label_claims_per_client` (default: four times `max_tunnels_per_client`, at least 40; `-1` turns it off) is the number of permanent names one client may hold. Past it the registration fails with `limit_exceeded`.
- `limits.label_claim_ttl` (default `720h`, 30 days; negative turns it off) drops a claim that no registration has used for that long; every registration of the tunnel renews it and the claims of tunnels that are online never expire. The server sweeps expired claims at start, at most once an hour on registrations, and at once when a client reaches its limit (at most once a minute). HTTP and SSH names share the claim table too, so a name used by one kind is not given to another pair for the other kind (a rare false conflict that `release-label` resolves).

### Tenants share one registrable domain

Every tunnel lives under `tun.example.com`, so a tunnel can set cookies for the whole domain (`Domain=tun.example.com`), which every other tunnel and the control host then receive (cookie tossing, session fixation). For a server shared by mutually untrusting users, give the tunnels their own domain that is not used for anything else, and consider adding it to the [Public Suffix List](https://publicsuffix.org/) (as ngrok, GitHub Pages and others do for their user content domains): browsers then refuse domain-wide cookies on it.

### Taken-over sessions

A new login with a client's token replaces its live session; the old connection receives `session_replaced` and stops (it does not reconnect, so two machines do not fight over the name). A stolen token is used the same way, so the server logs every replacement as a warning with the new and old addresses and whether they match (`session replaced by a newer login`). Watch for it, and revoke the token if the new address is not yours.

### Directory permissions

At startup `portholed` tightens `data_dir` and `<data_dir>/certs` to mode `0700` if they are accessible to group or others (as OpenSSH does for host keys) and logs a warning when it does or when it cannot.

## Behind a reverse proxy

`portholed` can run in plain HTTP on loopback behind a proxy that terminates TLS and handles the wildcard certificate. Set `tls.mode: off`, bind to loopback and trust the proxy's `X-Forwarded-For`:

```yaml
version: 1
domain: tun.example.com
listen: "127.0.0.1:8080"
tls:
  mode: off
trust_proxy_headers: true
tcp_port_range: "20000-29999"
data_dir: /var/lib/porthole
```

[deploy/Caddyfile.example](../deploy/Caddyfile.example) is a ready Caddy configuration (wildcard certificate via DNS-01, which needs a DNS provider module compiled into Caddy; WebSocket upgrades and unbuffered streaming responses are handled). TCP and SSH tunnels do not pass through the proxy: `portholed` listens on the ports of `tcp_port_range` (and on the SSH gateway port) directly, so open them in your firewall.

How `X-Forwarded-For` is read (it feeds the per-IP limits, the failure limiter, the audit log, the request log and the address shown to your local service):

- Proxies append the address of the peer they received the request from, so the *left* side of the header is whatever the visitor sent and can be forged. `portholed` reads it from the right.
- With `trusted_proxies` set (list your proxy's addresses or networks, here `127.0.0.1`), the header is honoured only when the direct peer is in that list, and the visitor is the right-most address that is **not** itself a trusted proxy. A direct connection from anywhere else is taken at face value and its header ignored, so a server that is also reachable without the proxy cannot be spoofed.
- Without `trusted_proxies` the right-most address is used: it is what the single proxy in front of you saw. That is correct for exactly one proxy hop and wrong when the port is reachable directly, so set `trusted_proxies`.
- A header that is missing or whose relevant entry is not an IP address falls back to the peer's own address.

```yaml
trust_proxy_headers: true
trusted_proxies: ["127.0.0.1"]
```

(If `proxy_protocol` is on as well, the peer address is the one from the PROXY header, and `X-Forwarded-For` is honoured only when that address is in `trusted_proxies`.) At startup `portholed` warns when it listens on a loopback or private address with neither `trust_proxy_headers` nor `proxy_protocol`: behind a proxy every visitor then shares the proxy's address in all per-IP limits.

### Behind Traefik or Dokploy (TLS passthrough)

A proxy that owns ports 80 and 443 but cannot issue a wildcard certificate (Traefik without a DNS-01 provider, the default in Dokploy) can instead pass the TLS connection through by SNI and leave certificates to `portholed` (mode `acme`): a Traefik TCP router with ``HostSNI(`tun.example.com`)`` and a `HostSNIRegexp` for `*.tun.example.com`, `tls.passthrough=true`, forwarding to the HTTPS port of the container, plus plain HTTP routers for the same hosts forwarding to `http_listen` (HTTP-01 and the redirect). TCP and SSH tunnel ports are published directly. [deploy/dokploy-compose.yaml](../deploy/dokploy-compose.yaml) is a ready compose file: in Dokploy create a Compose service, choose Raw and paste it, then set `PORTHOLED_DOMAIN` and your domain in the labels.

Passthrough hides the visitor: every connection arrives from Traefik, so per-address limits, the SSH gateway failure limiter, the request log and the audit log would all see Traefik's address. There is no `X-Forwarded-For` either, because the proxy never reads the encrypted HTTP. The fix is the PROXY protocol: Traefik writes a small header with the real address in front of the stream (label `traefik.tcp.services.<name>.loadbalancer.proxyProtocol.version=2` on the TCP service) and `portholed` reads it:

```yaml
proxy_protocol: true
trusted_proxies: ["10.0.1.0/24"]   # example: the subnet of the Docker network Traefik is on
```

`trusted_proxies` is the list of peers that may state any visitor address, so keep it as narrow as possible: the exact subnet of the network Traefik shares with `portholed` (`docker network inspect dokploy-network -f '{{(index .IPAM.Config 0).Subnet}}'`), not the broad private ranges `10.0.0.0/8` or `172.16.0.0/12`. Every container in a listed subnet can connect to `portholed` directly and forge the address, so on Dokploy, where all your apps share `dokploy-network`, prefer a network of its own for Traefik and `portholed` if you can set that up. A wrong value fails closed: Traefik is then not trusted, its header is refused and HTTPS stops working.

- Applies to the HTTPS listener. The SSH gateway is wrapped only with `proxy_protocol_ssh: true` (for a gateway that sits behind a TCP proxy which sends the header); by default it is published directly and sees the real peer. The metrics listener and TCP tunnel ports are not affected: they are reached directly.
- A peer inside `trusted_proxies` must send a header (v1 or v2); a connection from it without one is refused. A peer outside the list must not send one (the connection is refused), so a visitor cannot choose its own address; without a header it is served as an ordinary connection with its real address. The header must arrive within 5 seconds.
- `trusted_proxies` takes addresses and CIDR ranges. `proxy_protocol: true` without it is a configuration error, so that "trust every sender" can never happen by accident.
- Traefik's HTTP routers cannot send the PROXY protocol, so the plain HTTP listener (`http_listen`: challenge and redirect) is left out unless you set `proxy_protocol_http: true` and the proxy sends it there. With the default it sees Traefik's address; it serves no tunnel traffic.

Pick one mechanism per proxy. `trust_proxy_headers` (`X-Forwarded-For`) is for a proxy that terminates TLS and speaks HTTP to `portholed` (`tls.mode: off`, the Caddy case above). The PROXY protocol is for a proxy that forwards raw TCP, which is TLS passthrough and, with `proxy_protocol_ssh`, the SSH gateway behind a TCP load balancer. The Caddy equivalent is the `proxy_protocol` listener wrapper with an `allow` list; the Go library used here, [pires/go-proxyproto](https://github.com/pires/go-proxyproto), is the one Traefik and Caddy build on.

## Docker

See [Installation: Docker](install.md#docker) for a `docker run` example with a certificate mounted from `/etc/letsencrypt`.

### Docker Compose

[deploy/compose.yaml](../deploy/compose.yaml) builds the image from source and runs it read-only, as a non-root user, without capabilities. From the repository root:

```console
$ cp deploy/portholed.example.yaml deploy/portholed.yaml        # then set the domain and the TLS mode
$ docker compose -f deploy/compose.yaml up -d --build
$ docker compose -f deploy/compose.yaml exec portholed portholed token create --name home
```

With the default `acme` mode the example publishes ports 80 and 443 and keeps the certificates in the data volume. For mode `files` mount the certificates as `deploy/tls/fullchain.pem` and `deploy/tls/privkey.pem`, readable by uid 65532. The example publishes a small port range (`20000-20099`, kept in sync with `PORTHOLED_TCP_PORT_RANGE`, because publishing thousands of ports is slow with the default Docker networking) and the SSH gateway on `2222` (`PORTHOLED_SSH_LISTEN`).

## SSH gateway

The SSH gateway lets people reach a machine behind NAT by name with stock OpenSSH, through the server as a jump host (`ssh -J tun.example.com:2222 user@home`); see [SSH by name](ssh.md) for the user's view. It is off unless `ssh_gateway.listen` is set:

```yaml
ssh_gateway:
  listen: ":2222"
  max_conns_per_tunnel: 256
```

or `PORTHOLED_SSH_LISTEN=:2222`. Open that port in the firewall (port 22 of the VPS belongs to its own sshd).

- The gateway is not a shell: it accepts only `direct-tcpip` channels and refuses sessions, `exec`, `tcpip-forward`, agent and X11 forwarding, so logging in to the server through it is impossible, and it never sees the SSH plaintext between the visitor and the target machine.
- On first start it creates an ed25519 host key, `<data_dir>/ssh_host_ed25519_key` (mode 0600), and logs its SHA256 fingerprint. `portholed ssh-hostkey` prints the fingerprint again (it reads the same `--config`). Give the fingerprint to your users so they can compare it on their first connection. Back up the key file or the clients' `known_hosts` entries break when it is lost.
- Limits: a handshake deadline of 10 s, failed authentication rate-limited per source IP, at most `max_conns_per_tunnel` concurrent channels per tunnel, idle connections without channels closed after 60 s.
- Without a gateway, a plain `porthole ssh` falls back to a public TCP port with a warning.

Design and rejected alternatives: [ADR 0003](adr/0003-ssh-gateway-and-port-reservations.md).

## Request log and inspection

The server terminates TLS for HTTP tunnels, so it records every proxied request (time, tunnel, visitor IP, method, host, path, masked query, status, latency, body bytes, user agent) in a ring buffer in memory. TCP and SSH gateway connections are recorded as metadata only. Nothing is written to disk.

A tunnel started with `porthole http --inspect` (or `inspect: true` in `tunnels.yaml`) also keeps request and response **headers and bodies**, up to 64 KiB of each body, so an operator or an agent can see what a webhook sent and replay it. Bodies carry credentials and personal data, so this is off by default and chosen per tunnel; set `traffic.allow_inspect: false` to forbid it on this server. `Cookie`, `Set-Cookie` and every header whose name contains `token`, `secret`, `api-key`, `apikey`, `auth`, `session` or `signature` (case-insensitive: `Authorization`, `X-Api-Key`, `X-Auth-Token`, `X-Csrf-Token`, `X-Amz-Security-Token`, `X-Hub-Signature-256`, ...) are always stored as `REDACTED`, and a replay does not send them. In the logged query string the values of parameters whose name contains `token`, `key`, `password`, `passwd`, `secret`, `auth`, `signature`, `session` or `credential`, starts with `x-amz-`, or is exactly `code`, `sig`, `sid`, `jwt`, `otp` or `ticket` are masked. Secrets in the path (`/reset/<token>`) and in bodies are not found: bodies are stored as they are. `traffic.max_detail_bytes` bounds the memory of all stored details; the details of the oldest requests are dropped first.

The admin API (unix socket, or a bearer token over the public listener) serves the logs under `/_porthole/admin/v1/`:

| Endpoint | Scope | Result |
|---|---|---|
| `GET requests` | `admin:read` | Logged requests, newest first. Filters: `tunnel`, `client`, `status_class` (1-5), `path_prefix`, `ip`, `since` (RFC 3339 or a duration such as `15m`), `limit`; `aggregate=1` returns status classes, top paths and visitors, latency percentiles and a per-minute count instead |
| `GET requests/{id}` | `admin:read`; headers and bodies need `admin:traffic` | One request, with `detail` for inspected requests |
| `POST requests/{id}/replay` | `admin:traffic` | Sends the recorded request again into its tunnel and returns the new log entry (`replay_of` is the original id). Audited as `request.replay`. Refused with `409` if the tunnel is offline or no longer inspected, the request was not inspected, its detail was dropped, or its body was truncated. Headers that were redacted are not sent |
| `GET connections` | `admin:read` | TCP and SSH connections (`tunnel`, `client`, `kind`, `ip`, `outcome`, `since`, `limit`) |
| `GET auth-failures` | `admin:read` | SSH gateway authentication failures (`since`, `limit`) |

## Metrics

Set `metrics_listen` (for example `127.0.0.1:9090`) to serve Prometheus metrics at `/metrics` and the Go profiler at `/debug/pprof/` on a separate listener. It is off by default. The listener has no authentication and the profiler can expose memory contents and slow the server down, so bind it to a loopback address and scrape it from the same host (Prometheus agent, node-local collector) or through a proxy that authenticates. Any other address works but logs a warning at start.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `porthole_build_info` | gauge | `version` | Always 1; the version of `portholed` |
| `porthole_sessions` | gauge | - | Connected client sessions |
| `porthole_tunnels` | gauge | `kind` (`http`, `tcp`, `ssh`) | Registered tunnels |
| `porthole_http_requests_total` | counter | `status_class` (`1xx` to `5xx`) | Requests to tunnel hosts, by response status |
| `porthole_http_request_duration_seconds` | histogram | - | Request time until the response is fully written; long-lived streaming responses land in the top buckets |
| `porthole_bytes_total` | counter | `direction` (`in` toward the tunnel client, `out` toward the visitor), `kind` | Relayed bytes. For `http` only request and response bodies are counted, and a WebSocket upgrade counts as one `101` response without its frames |
| `porthole_tcp_connections_total` | counter | `kind` (`tcp`, `ssh`), `outcome` | Visitor connections to TCP tunnels and SSH gateway channels. `outcome`: `accepted`, `limit` (tunnel at its connection limit), `stream_error` (the client did not open a stream), `refused` (`ssh` only: unknown or not permitted target) |
| `porthole_ssh_gateway_auth_failures_total` | counter | - | Failed token logins at the SSH gateway |
| `porthole_handshake_failures_total` | counter | `reason` | Control handshakes answered with an error; `reason` is the protocol error code (`unauthorized`, `unsupported_version`, `limit_exceeded`, ...) |
| `porthole_acme_certificates_total` | counter | `result` (`obtained`, `failed`) | Certificate issuance and renewal attempts in mode `acme` |

The standard `go_*` and `process_*` metrics are included. Metrics are never labelled by tunnel, client, host or address, so the number of series does not grow with traffic. Bytes of a TCP or SSH connection are added when the connection ends.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: portholed
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

Profiling, for example a 30 second CPU profile: `go tool pprof http://127.0.0.1:9090/debug/pprof/profile?seconds=30`. From your workstation use an SSH port forward (`ssh -L 9090:127.0.0.1:9090 tun.example.com`) instead of opening the port.

## Opening a tunnel on a client's machine

An operator can ask a connected machine to open a tunnel, for example "open an SSH tunnel on `home`", without logging in to that machine:

```console
$ portholed admin open home http 3000 --name blog
tunnel "blog" (http) is open on home: https://blog-home.tun.example.com
$ portholed admin open home ssh --private          # 127.0.0.1:22 through the SSH gateway
$ portholed admin open home tcp 192.168.1.5:80 --json
```

`kind` is `http`, `tcp` or `ssh`; `local` is a port, `host:port` or, for `ssh`, nothing (`127.0.0.1:22`). Flags: `--name`, `--private` (ssh), `--remote-port` (tcp). The command talks to the admin socket, so it needs no token. The same request is `POST /_porthole/admin/v1/clients/{name}/tunnels` with a JSON body (`{"kind":"http","local_addr":"3000","name":"blog"}`) and a bearer token with the `admin:remote` scope. It returns `{"ok":true,"tunnel":{"name","kind","public_url","ssh_jump"}}`.

What has to be true, and what the error codes say:

| Code | Meaning |
|---|---|
| `not_found` | No client of that name is connected |
| `client_unsupported` | The client does not accept requests: it is not the `porthole daemon` / `porthole start`, or it is too old |
| `remote_control_disabled` | The client's token does not allow remote control |
| `not_allowed` | The machine refused: the target is not allowed by `allow_remote` of its tunnels file (by default only loopback targets and `ssh`; [client guide](client.md#remote-requests)) |
| `name_taken`, `limit_exceeded`, `port_unavailable` | The server refused to register the tunnel, as for any tunnel |
| `timeout` | The client did not answer within 15 seconds |

The tunnel is a runtime tunnel of the daemon: it survives reconnects, not a daemon restart, and `porthole tunnels` and `porthole close` show and remove it. Every request is written to the audit log as `tunnel.remote_open`, with the acting token and the request (kind, local address, name), never a secret. The server cannot widen what the machine allows.

## Command reference

| Command | Purpose |
|---|---|
| `portholed serve [--config] [--log-level]` | Run the server |
| `portholed join create --name N [--ttl 15m] [--scopes ...] [--max-tunnels N] [--expires 30d] [--no-remote-control]` | Create a one-time join link |
| `portholed join list [--all]`, `join revoke <id>` | List and revoke join links |
| `portholed token create --name N [--expires 30d] [--scopes ...] [--max-tunnels N] [--no-remote-control]` | Create a token |
| `portholed token list [--all]` | List tokens |
| `portholed token revoke <id\|name>` | Revoke a token |
| `portholed admin open <client> <http|tcp|ssh> [local] [--name] [--private] [--remote-port]` | Ask a connected client to open a tunnel; prints its address |
| `portholed admin release-label <label>` | Free a hostname label that is claimed for good by a client's tunnel |
| `portholed ssh-hostkey` | Print the fingerprint of the SSH gateway host key |
| `portholed version` | Print the version |

The global flag `-c, --config` (default `/etc/porthole/portholed.yaml`; empty means environment variables only) applies to all of them.

### Machine-readable output (`--json`)

The global flag `--json` makes a command write JSON to stdout instead of text (one document per command):

| Command | Document |
|---|---|
| `token create` | `id`, `name`, `token` (the secret: this is the only place that ever shows it), `last4`, `scopes`, `max_tunnels`, `created_at`, `expires_at`, `server_url`, `login` (the `porthole login ...` command line) |
| `token list` | An array of tokens, without secrets |
| `token revoke` | `id`, `name`, `revoked`, `already_revoked` |
| `admin open` | `client`, `name`, `kind`, `public_url`, `ssh_jump` |
| `ssh-hostkey` | `fingerprint`, `path` |
| `version` | `name`, `version`, `go`, `os`, `arch` |

`serve` writes nothing to stdout; its log is always JSON on stderr. A failure writes `{"error":{"code":"...","message":"..."}}` to stdout (without `--json`: `portholed: <message>` to stderr).

### Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Any other failure: database, a token that does not exist, the server stopping with an error |
| 2 | Usage error: unknown command, bad flag or argument, an invalid `--name`, `--expires`, `--scopes` or `--log-level` |
| 5 | `admin open`: the request was refused (`not_allowed`, `remote_control_disabled`, `client_unsupported`, `name_taken`, ...) |
| 78 | The configuration could not be loaded or is invalid |

The client-side statuses 3, 4 and 6 are not used by `portholed`; see the [client guide](client.md#exit-status).

## Security

Please report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md), not in public issues. The security model is described in [DESIGN.md](../DESIGN.md#4-security-model).
