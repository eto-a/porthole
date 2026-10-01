# porthole — design

Status: draft for v0.1 · Last updated: 2026-10-01

porthole is a self-hosted, open-source (Apache-2.0) alternative to ngrok. You run one server, `portholed`, on a
machine with a public IP and a domain. On any machine behind NAT you run the client, `porthole`, and expose local
services with one command:

```console
$ porthole login https://tun.example.com ph_3kq9w2m1z8xa_....     # once per machine
$ porthole http 8080
https://http-8080-home.tun.example.com  ->  localhost:8080
$ porthole tcp 7575
tcp://tun.example.com:20017  ->  localhost:7575
$ porthole ssh
ssh -p 20018 <user>@tun.example.com  ->  localhost:22
```

All tunnel configuration happens on the client. The server operator only issues tokens.

This document records *what* we build and *why*, with references to the projects each decision was taken from.
Detailed wire format: [docs/protocol.md](docs/protocol.md). Individual decisions: [docs/adr/](docs/adr/).

---

## 1. Goals and non-goals

**Goals**

1. Client-driven tunnels: `porthole {http|tcp|udp|ssh} <port>`; the server allocates the public address and returns it.
2. Protocols: HTTP(S) incl. WebSocket, raw TCP, UDP, and a first-class SSH experience.
3. Token-based auth managed on the server: create / list / revoke / expire, per-token limits and scopes.
4. Many named clients per server; every client sees only its own tunnels and names.
5. Outbound-only from the client; works through corporate firewalls (TLS on 443).
6. Single static binary per side, trivial to deploy (systemd, Docker), production-grade defaults.
7. Code quality and supply-chain hygiene on par with large Go projects (tailscale, caddy, prometheus).

**Non-goals (for now)**

- Mesh VPN / peer-to-peer (Tailscale, NetBird solve that).
- A hosted public service. porthole is meant to be self-hosted; a public free instance invites abuse
  (see bore's phishing problems: ekzhang/bore#150, #141).
- Multi-node HA server cluster (single server first; the design must not preclude it).
- A web UI, request inspection UI, traffic replay. Management is CLI- and agent-first (§3.11).

## 2. Prior art and what we take from it

| Project | Take | Avoid |
|---|---|---|
| frp (Go, Apache-2.0) | Control channel + per-request streams; `NewProxy`/`NewProxyResp` returning a ready address; port reservation per proxy name for 24h; per-client limits; versioned frame with size cap | Single shared token; client-asserted `user` field; JSON+base64 UDP; goroutine leaks on re-login (fatedier/frp#5391); auth key ≠ routing key (CVE-2026-40910) |
| rathole (Rust, Apache-2.0) | Challenge/nonce idea; small codebase; UDP framing with source address | Control channel that never reads (rapiz1/rathole#470); silent UDP truncation at 2048 B; static server-side service list |
| chisel (Go, MIT) | Transport over WebSocket on 443; keepalive ping with timeout; backoff with jitter | Password users in plaintext authfile; ACL checked only at handshake (CVE-2026-48113, GHSA-397r-r4gr-x5pg) |
| sish (Go, MIT) | Server-side allocation of subdomains/ports with random fallback; Host/SNI routing; SSH gateway via `direct-tcpip` (ProxyJump) | No ownership of names (antoniomika/sish#313); no rate limits (#315); slowloris on TLS (#349) |
| bore (Rust, MIT) | Tiny protocol that fits on one page; hard timeouts; hard frame-size limit | Shared secret for everybody; no TLS; no reconnect |
| cloudflared (Go, Apache-2.0) | QUIC first with HTTP/2-style fallback; dedicated control stream; server-driven `retryAfter`; UDP sessions over QUIC datagrams with idle hint; datagram payload ≤ 1280 | Cap'n Proto; forked quic-go; vendor-specific edge discovery |
| zrok (Go, Apache-2.0) | Account token → per-environment identity; reserved vs ephemeral names; open/closed shares | Five-component deployment; dependency on an overlay network |
| Pangolin, Teleport (AGPL — ideas only, no code) | Token stored as hash + last chars; one-time setup token printed at first start; short-lived join tokens | Licensing; complexity |
| tailscale, caddy, prometheus, etcd | Repo layout, CI hardening, release signing, lint config, admin endpoint bound to localhost | — |

## 3. Architecture

```
            public internet                                  │  private network (NAT)
                                                             │
 browser ──HTTPS──▶┐                                         │
 ssh/tcp client ──▶│  portholed                              │      porthole (client)
 udp client ──────▶│  ┌───────────┐   ┌──────────────┐       │     ┌──────────────┐     ┌─────────────┐
                   └─▶│ listeners │──▶│  registry    │◀══════╪═════│  session     │────▶│ localhost:N │
                      │ :443 http │   │ tunnels,     │  one  │     │  (reconnect) │     │ service     │
                      │ :2xxxx tcp│   │ sessions     │  mux  │     └──────────────┘     └─────────────┘
                      └───────────┘   └──────┬───────┘ session (WS+yamux, later QUIC)
                                             │
                                       ┌─────▼─────┐
                                       │  store    │ SQLite: tokens, reservations
                                       └───────────┘
```

- The client opens **one** outbound session to the server and keeps it alive with reconnect + backoff.
- Inside the session: one **control stream** (opened by the client first) and one **data stream per proxied
  connection** (opened by the server when a visitor connects).
- The client never interprets proxied bytes: every data stream is "dial the local target, copy both ways".
  All protocol awareness (HTTP Host routing, TLS, WebSocket upgrade) lives on the server.

### 3.1 Transport

| | v0.1 | v0.2+ |
|---|---|---|
| Primary | WebSocket over TLS on 443 (`coder/websocket`) + `hashicorp/yamux` | QUIC on UDP/443 (`quic-go` ≥ 0.63) with own ALPN, UDP via RFC 9221 datagrams |
| Fallback | — | WebSocket + yamux (same control protocol); via HTTP CONNECT proxy if configured |
| Selection | — | `auto`: try QUIC, fall back on handshake timeout, re-probe QUIC periodically (cloudflared `connection/protocol.go`) |

Why WebSocket first: it is the fallback we need anyway (IETF estimates 3–5 % of networks block UDP; corporate
networks block more), it shares port 443 and the TLS certificate with HTTP tunnels, and it passes through HTTP
proxies and CDNs (chisel). QUIC is an optimisation and is the only clean way to carry UDP, so it lands with UDP
tunnels in v0.2. Both implement one interface (`internal/transport.Session`), so the rest of the code does not care.

Why yamux and not smux: per-stream flow control (smux v1 shares one buffer per session), widely deployed (frp uses
a fork), MPL-2.0 is compatible with distributing an Apache-2.0 binary. Why `coder/websocket` and not gorilla: active
releases (gorilla's last release is from 2024), used by tailscale.

Rejected: SSH as the control protocol (chisel/sish). It gives multiplexing for free, but auth is username/password or
keys rather than revocable server-issued tokens, and it complicates UDP. Cap'n Proto RPC (cloudflared): heavy
dependency for ~10 message types.

### 3.2 Control protocol (summary — full spec in docs/protocol.md)

- Every control message is a length-prefixed frame: `uint32 big-endian length | JSON object`, max 64 KiB.
  The object has a `type` field. JSON keeps the protocol debuggable and is never on the data path; the size cap
  and strict decoding (unknown fields rejected for known types) make it safe on untrusted input.
- Handshake (client → server): `hello{protocol_version, token, client_version, os}`;
  response `hello_ok{client_name, session_id, server_version, heartbeat_interval}` or `error{code, message,
  retry_after}`. The server accepts protocol versions N and N-1. Handshake deadline: 10 s.
- Tunnel lifecycle: `register{req_id, kind, name?, options}` → `registered{req_id, tunnel_id, public_url}` or
  `error`; `unregister{tunnel_id}`. The server pushes `tunnel_closed{tunnel_id, reason}` when it drops a tunnel
  (e.g. token revoked, limits changed).
- Liveness: `ping{seq}` / `pong{seq}` every 15 s from the server, session closed after 3 missed pongs. The control
  stream is read continuously on both sides, so half-closed connections are detected (rathole#470).
- Data stream: the server opens a stream and writes one frame `stream{tunnel_id, remote_addr}`, then raw bytes.

### 3.3 Identity and tokens

- Token format: `ph_<id>_<secret>`. `id` is 12 lowercase base32 chars (public, used for lookup and display);
  `secret` is 32 random bytes in base32 (256 bits). The `ph_` prefix lets secret scanners detect leaks.
- The server stores `sha256(secret)` only, plus the last 4 chars for display. Comparison is constant-time
  (`crypto/subtle`). A plain hash is sufficient because the secret is 256 bits of entropy; a slow KDF buys nothing.
- **A token is a client identity.** Each token has a unique `name` (`home`, `office-nas`) that becomes the client
  name. The client name is never taken from the client's request (frp's `user` field mistake).
- Fields: `id, name, secret_hash, last4, scopes, max_tunnels, created_at, expires_at, revoked_at, last_used_at`.
- Scopes (v0.1): `tunnel:http`, `tunnel:tcp`, `tunnel:udp`; default all. Later: `admin`, `connect:<client>`
  for private tunnels.
- Authorization is evaluated on **every** `register` (and for private tunnels on every visitor connection), not only
  at handshake (chisel CVEs). The token row is re-read from the store each time.
- Revocation takes effect on live sessions: the server re-validates the tokens of live sessions every 30 s and on
  every `register`, and closes sessions whose token is revoked or expired.
- Management (v0.1): `portholed token create|list|revoke` operate directly on the server's database (SQLite WAL
  allows this while the server runs). An admin API bound to localhost/unix socket replaces this in v0.3 (§3.11).
- Future: one-time setup token printed at first start (Pangolin), short-lived join tokens that enroll a machine and
  are exchanged for a long-lived identity (Teleport, zrok).

### 3.4 Names and addresses

- HTTP: `https://<tunnel>-<client>.<domain>`. Default tunnel name is derived from the request (`http-8080`), so the
  URL is stable across restarts; `--name blog` gives `https://blog-home.<domain>`. One DNS label keeps a single
  wildcard certificate (`*.domain`) sufficient. Uniqueness of the full label is enforced by the registry; because a
  client can only register names with its own suffix, one client can never take over another client's hostnames
  (sish#313).
- TCP/UDP: a port from a configured range (default 20000–29999). The port is reserved for `(client, tunnel name)`
  for 24 h after the tunnel goes away, so reconnecting clients get the same address (frp `server/ports.go`).
  Reservations are persisted in the store in v0.2 (ADR 0003); in-memory in v0.1.
- SSH (v0.1): `porthole ssh` = TCP tunnel named `ssh` to `localhost:22`, prints a ready `ssh -p` command.
- SSH gateway (v0.2): `ssh -J <domain>:2222 user@home` (or `ProxyJump` in `~/.ssh/config`) with stock OpenSSH and
  nothing installed on the visitor. `portholed` runs a forwarding-only SSH server that accepts `direct-tcpip` channels
  and routes them by name to the client's `ssh` tunnel; the inner SSH session is end to end, so the target's sshd
  authenticates the user and the server never sees plaintext (sish TCP aliases). Routing by SSH username was rejected:
  the gateway would have to terminate SSH (sshpiper model). Details: [ADR 0003](docs/adr/0003-ssh-gateway-and-port-reservations.md).
- Private tunnels (v0.2): only for the SSH gateway. `porthole ssh --private` makes the gateway ask for a porthole token
  (same client or scope `connect:<client>`) as the SSH password before forwarding. HTTP tunnels stay public: a browser
  login flow is not planned.

### 3.5 Server listeners and routing

One HTTPS listener (default `:443`, configurable; plain HTTP behind a reverse proxy is supported):

| Host | Path | Action |
|---|---|---|
| `<domain>` | `/_porthole/v1/connect` | WebSocket upgrade → client session |
| `<domain>` | `/healthz` | liveness |
| `<label>.<domain>` | any | reverse proxy into the tunnel owning `label` (including `/healthz`: it is the application's) |
| any Host outside `<domain>` (bare IP, `IP:port`, foreign name) | `/healthz` | liveness, so that load balancers probing by IP work |
| anything else | | 404 |

`/healthz` answers on the bare domain and on every Host that is not under `<domain>`; a name under the domain that
is not a valid tunnel host (`a.b.<domain>`, an unknown label) is a 404. For comparison: frp serves `/healthz` on the
separate dashboard listener (`server/api_router.go`), so it never competes with vhost routing, and a code search of
sish found no health endpoint at all; porthole has a single public listener, so the Host decides.

HTTP tunnels use `net/http/httputil.ReverseProxy` with a custom `DialContext` that opens a data stream to the client.
This gives correct HTTP/1.1 keep-alive, WebSocket upgrades (ReverseProxy supports `Upgrade` since Go 1.12),
`X-Forwarded-*` headers, and streaming. The routing decision and the access decision use the same key (the
tunnel looked up by Host) — frp's CVE-2026-40910 was a mismatch between the two.

TCP tunnels each get a `net.Listener` on their port; every accepted connection becomes a data stream.

TLS: v0.1 loads a certificate from files (e.g. a wildcard certificate from certbot DNS-01) or runs plain HTTP behind
an existing reverse proxy. A renewed certificate is picked up without a restart: `portholed` compares the file
modification times at most once a minute on a handshake, and reloads immediately on `SIGHUP` (Unix; the systemd unit
has `ExecReload=/bin/kill -HUP $MAINPID`, so `systemctl reload portholed` works as a certbot deploy hook). A failed
reload is logged and the previous certificate stays in use. (Same convention as Prometheus and Traefik's file
provider, which reload on SIGHUP; Caddy ignores SIGHUP and uses `caddy reload`.) v0.2 adds automatic certificates via `certmagic` with DNS-01 (`libdns` providers) for the
wildcard, obtained once rather than per tunnel (boringproxy issues one per domain).

### 3.6 Client

- `porthole login <server-url> <token>` stores `{server, token}` in `$XDG_CONFIG_HOME/porthole/config.yaml`
  (file mode 0600; `%AppData%` on Windows).
- v0.1: `porthole http|tcp|ssh` runs in the foreground (like ngrok), prints the public URL, reconnects with
  exponential backoff + jitter (base 1 s, max 60 s, honours `retry_after`), and re-registers its tunnels after
  reconnect.
- v0.2: `porthole daemon` (systemd unit `porthole.service`) holds the session and serves a local HTTP+JSON API on a
  unix socket (tailscale `tailscaled` model); `porthole http|tcp|ssh` adds an attached tunnel to a running daemon and
  falls back to the in-process v0.1 behaviour when there is none. Details: [ADR 0002](docs/adr/0002-client-daemon-and-tunnels-file.md).
- v0.2: `tunnels.yaml` declares several tunnels at once (`porthole start` in the foreground, or the daemon), like
  `ngrok.yml` and frp's `frpc.toml`; credentials stay in `config.yaml`, so the tunnels file holds no secrets.

### 3.7 Lifecycle and resource safety

Lessons from frp#5391 and rathole#470 drive this:

- Each client session owns a `context.Context`; closing the session cancels it, which closes all listeners, data
  streams and goroutines it started. Every goroutine is started with that context and tracked by an
  `errgroup`/`sync.WaitGroup`; tests assert no goroutine leaks (`go.uber.org/goleak`).
- Re-login of the same client (same token) replaces the old session; the old one is closed **without** blocking the
  new login on the old one's shutdown.
- Hard limits everywhere: handshake deadline, control frame size (64 KiB), max tunnels per token (default 10), max
  concurrent streams per session (yamux `AcceptBacklog`), `ReadHeaderTimeout`/`IdleTimeout` on the HTTP server
  (slowloris), per-IP rate limit on failed handshakes (`golang.org/x/time/rate`).

### 3.8 Storage

SQLite via `modernc.org/sqlite` (pure Go, keeps `CGO_ENABLED=0` static builds), WAL mode, schema migrations
embedded with `embed`. Postgres support is possible later behind the `store.Store` interface. JSON-file storage was
rejected (boringproxy lost tunnels on corrupted JSON).

### 3.9 Configuration

Server: YAML file with a `version: 1` field, strict decoding (unknown keys are errors), overridable by
`PORTHOLED_*` environment variables and flags; secrets may be read from files. Minimal config:

```yaml
version: 1
domain: tun.example.com
listen: ":443"
tls:
  cert_file: /etc/porthole/tls/fullchain.pem
  key_file: /etc/porthole/tls/privkey.pem
tcp_port_range: "20000-29999"
data_dir: /var/lib/porthole
```

Optional `server_url` (env `PORTHOLED_SERVER_URL`) is the address clients connect to, as printed in the
`porthole login <server_url> <token>` hint (compare `ROOT_URL` in Gitea, `SiteURL` in Mattermost). When empty it is
derived from `public_scheme`, `domain` and `public_port`. It matters when the control endpoint is served over HTTPS
by a proxy while tunnel hosts are plain HTTP. Validation: absolute `http`/`https` URL, no path, query or fragment
(a trailing `/` is dropped).

### 3.10 Observability

`log/slog` (JSON on the server, text on the CLI); tokens are never logged (only `id`). `/healthz` on the main
listener (any Host that is not a tunnel host, see 3.5); `/metrics` (Prometheus) and `/debug/pprof` on a separate listener bound to localhost (v0.2). Graceful
shutdown on SIGINT/SIGTERM with a configurable grace period.

### 3.11 Management by LLM agents (v0.3)

porthole deliberately has **no web UI**. Operators manage it from the CLI or by delegating to an LLM agent
(Claude Code or any MCP client): "issue a 7-day token for the laptop", "who is connected?", "close the tunnel on
8080". The building blocks:

1. **Admin API** on the server, bound to a unix socket or `127.0.0.1` only, authenticated with tokens carrying an
   `admin:*` scope. It exposes clients, tunnels and tokens; the `portholed token` CLI moves onto it instead of
   opening the database directly. This is the only management surface; everything below is a thin client.
2. **MCP server**: `portholed mcp` (stdio) for operators and `porthole mcp` for a client machine, built on the
   official `github.com/modelcontextprotocol/go-sdk` (also used by github/github-mcp-server and
   hashicorp/terraform-mcp-server). Tools are grouped into toolsets with a `--read-only` mode that takes priority
   over everything else, following github-mcp-server's `--toolsets`/`--read-only` design: e.g. `clients`
   (`list_clients`, `disconnect_client`), `tunnels` (`list_tunnels`, `open_tunnel`, `close_tunnel`), `tokens`
   (`create_token`, `revoke_token`, `list_tokens`).
3. **Machine-readable CLI**: `--json` on every command and documented exit codes, so an agent without MCP can
   drive porthole through a shell just as well.
4. **Least privilege and audit**: an agent gets its own token with narrow scopes (`admin:read`, `admin:tokens`, ...);
   every mutating admin call is written to an append-only audit log with the acting token id. Secrets are only ever
   returned once (token creation) and never echoed into logs or tool results afterwards.

## 4. Security model

- Threats in scope: unauthenticated internet attackers hitting the server; a malicious/compromised client trying to
  hijack other clients' names, exhaust resources or reach server-internal addresses; leaked tokens.
- The server only ever dials **from the client side**: a client cannot make the server connect to arbitrary
  addresses (no "remote" forwarding to server-side hosts as in chisel), which removes an SSRF class.
- Hostnames and ports a client may register are restricted by its identity and scopes.
- All HTML output uses `html/template` (zrok CVE-2026-40302 used `text/template`).
- No authentication bypass flags for "internal" paths (frp `AlwaysAuthPass`, CVE-2026-73564).
- Visitors of public HTTP tunnels are untrusted; the server strips hop-by-hop headers and sets `X-Forwarded-For`
  itself (overwriting client-supplied values).
- Full threat model: `THREAT_MODEL.md` (v0.2).

## 5. Repository layout

```
cmd/portholed/        server main (thin)
cmd/porthole/         client main (thin)
internal/proto/       control messages, frame codec, versions (fuzzed)
internal/transport/   Session interface; websocket+yamux implementation; QUIC later
internal/auth/        token format, generation, hashing, verification
internal/store/       Store interface + SQLite implementation + migrations
internal/server/      session handling, registry, port allocation, HTTP routing
internal/client/      session, reconnect, local forwarding
internal/config/      server config loading and validation
internal/cli/         cobra commands for both binaries
tests/e2e/            real-socket end-to-end tests (server + client in one process / as processes)
docs/                 protocol.md, adr/
```

Everything is `internal/` until someone needs a public Go API (tailscale and prometheus keep most code outside
`pkg/` as well).

## 6. Engineering practices

- Go 1.27, single module `github.com/eto-a/porthole`.
- `golangci-lint` v2 with `default: none` and an explicit list (gosec, staticcheck, errcheck, errorlint, govet,
  ineffassign, unused, bodyclose, sloglint, gocritic, revive, misspell, nolintlint, gofumpt, goimports).
- `go test -race -shuffle=on` on Linux, macOS, Windows; `govulncheck`; fuzz targets for the frame decoder, token
  parser and config loader (`go test -fuzz` in CI for a short time per target).
- GitHub Actions pinned by commit SHA, top-level `permissions: contents: read`, `zizmor` workflow lint,
  Dependabot (gomod + actions, grouped, monthly).
- Releases (v0.1 tag): goreleaser, `CGO_ENABLED=0 -trimpath`, cosign keyless signatures, SBOM (syft), GitHub
  artifact attestations.
- Community files: LICENSE (Apache-2.0), SECURITY.md (private vulnerability reporting), CONTRIBUTING.md (DCO
  sign-off), CODE_OF_CONDUCT.md (Contributor Covenant), issue/PR templates, ADRs in `docs/adr/` (MADR format).

## 7. Roadmap

| Version | Scope |
|---|---|
| **0.1** | `portholed` + `porthole`; WebSocket+yamux transport; tokens (create/list/revoke/expire) in SQLite; HTTP (incl. WebSocket) and TCP tunnels; `porthole ssh` as TCP:22; reconnect; cert from files; CI, lint, e2e tests |
| 0.2 — install and forget | `install.sh`, deb/rpm packages, GHCR image; client daemon + systemd; client config with several tunnels; SSH gateway by name (`ssh -J`); private SSH tunnels; persisted port reservations |
| 0.3 — managed by agents | Admin API (unix socket / localhost); MCP server with toolsets and read-only mode; `--json` everywhere; narrow admin scopes; audit log; join tokens; threat model |
| 0.4 — protocols | QUIC transport with auto fallback; UDP tunnels; basic auth and IP allowlists for HTTP tunnels; certmagic DNS-01; Prometheus metrics; bandwidth limits; TLS passthrough |

A web UI is a non-goal (see §3.11).

## 8. Open questions

- Should HTTP tunnels also support path-based routing for setups without wildcard DNS? (Decided: not in 0.x.)
- TLS passthrough tunnels (SNI routing without terminating TLS on the server) — useful for end-to-end TLS; candidate
  for 0.2.
- Multi-server HA: tunnels are bound to one server process; a shared store + sticky routing would be needed.
