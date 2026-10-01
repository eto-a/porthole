# 0002. Client daemon, local API and the tunnels file

- Status: accepted
- Date: 2026-10-01
- Issues: #22 (client daemon), #4 (tunnels file)

## Context

v0.1 runs every tunnel in a foreground `porthole http|tcp|ssh` process. The v0.2 goal is "install and forget": a
service that keeps several tunnels up across reboots, and a CLI that can add a tunnel to it. Prior art studied
(clones at tailscale `689a0c1`, cloudflared `059f86a`, frp `d20a232`, plus the public ngrok agent docs):

- **tailscale**: `tailscaled` exposes a LocalAPI as HTTP over a unix socket (`/var/run/tailscale/tailscaled.sock`,
  a protected named pipe on Windows) with a fixed fake Host and `/localapi/v0/` paths; requests carrying `Origin` or
  `Referer` are rejected; peer credentials (SO_PEERCRED) decide who may write; `watch-ipn-bus` streams events. The
  CLI only works through the daemon. Unit: `Type=notify`, `Restart=on-failure`.
- **frp**: `frpc.toml` with a `[[proxies]]` list; an admin HTTP API on loopback with basic auth
  (`/api/reload`, `/api/status`); `frpc reload` re-reads the config to find that API; reload validates the whole
  file first and then applies it as a diff, keeping the old set on error.
- **cloudflared**: `service install` writes a systemd unit and `/etc/cloudflared/config.yml` with an `ingress`
  list; credentials live in a separate 0600 file.
- **ngrok**: `ngrok.yml` with named tunnels/endpoints, `ngrok start --all|<names>`, `ngrok service install`, and an
  unauthenticated local API on `127.0.0.1:4040`.

## Decision

### Process model

- One binary: `porthole daemon` is a subcommand (as `tailscaled` is not, but frpc is one binary too). It owns one
  session to the server and a mutable set of tunnels, and serves the local API.
- The tunnel set = the tunnels file + *runtime* tunnels added over the local API. Runtime tunnels are never
  persisted: what runs after a reboot is exactly the tunnels file (auditable, like ngrok API tunnels).
- `porthole start [names...]` runs the tunnels file in the foreground without a daemon (ngrok `start`).
- `porthole http|tcp|ssh`:
  1. if a daemon socket is reachable, the tunnel is added to the daemon as an *attached* tunnel (removed when
     the CLI disconnects, i.e. on Ctrl-C), and the output is the same as in v0.1; `--detach` adds a runtime tunnel
     that stays until `porthole close <name>` or a daemon restart;
  2. if there is no socket (missing file or connection refused), it runs in-process exactly as in v0.1;
  3. if the socket exists but access is denied, it fails with a hint and never falls back: a standalone client
     with the same token would replace the daemon's session (DESIGN.md §3.7) and the two would evict each other.
  `--no-daemon` forces 2, `--daemon` requires 1.

### Files

Credentials and tunnels stay in separate files (ngrok/frp/cloudflared mix them; we keep the tunnels file free of
secrets so it can be committed and shared, while `config.yaml` stays 0600):

- `config.yaml` (written by `porthole login`): `server`, `token`, and new optional `token_file` (one line; refused
  if group/world-readable on Unix, like ssh keys).
- `tunnels.yaml`, strict decoding, 64 KiB cap:

```yaml
version: 1
server: https://tun.example.com   # optional; overrides config.yaml
tunnels:
  blog:                 # key = tunnel name (auth.ValidName)
    type: http          # http | tcp | ssh
    addr: 3000          # same grammar as the CLI target: "3000", ":3000" or "host:port"
  db:
    type: tcp
    addr: nas.local:5432
    remote_port: 20017  # tcp/ssh only, optional
  ssh:
    type: ssh           # tcp to 127.0.0.1:22 unless addr is given
  old:
    type: http
    addr: 8081
    enabled: false      # default true
```

  `token` is not an accepted key. No templating in v0.2 (if ever: `${VAR}` in decoded values, not in raw text as
  frp does).

Default paths:

| | system daemon (Linux, deb/rpm) | user mode (any OS) |
|---|---|---|
| config | `/etc/porthole/config.yaml` | `<UserConfigDir>/porthole/config.yaml` (as in v0.1) |
| tunnels | `/etc/porthole/tunnels.yaml` | `<UserConfigDir>/porthole/tunnels.yaml` |
| socket | `/run/porthole/porthole.sock` | Linux: `$XDG_RUNTIME_DIR/porthole/porthole.sock`; Windows: `%LocalAppData%\porthole\porthole.sock`; macOS: `<UserCacheDir>/porthole/porthole.sock` |

The CLI looks for the socket in this order: `--socket`, `$PORTHOLE_SOCKET`, user socket, system socket.

### Local API

HTTP/1.1 + JSON over a unix domain socket on every OS. `net.Listen("unix")` works on Windows 10 1803+ (verified on
Windows 11 with Go 1.27), so there is no named-pipe dependency; access on Windows is the ACL of the per-user
directory. Loopback TCP (frp, ngrok) is rejected: any local user and any browser page could reach it.

- Fixed Host `porthole`; requests with `Origin` or `Referer`, or another Host, get 403 (tailscale).
- Paths under `/v1/`; errors are `{"error":{"code":"...","message":"..."}}` with the `proto` error codes where
  they apply (`name_taken`, `invalid_request`, ...) plus `not_found` and `conflict`.
- `GET /v1/status`, `GET /v1/tunnels`, `POST /v1/tunnels` (`lifetime: attached|runtime`; attached responses are an
  NDJSON event stream and the tunnel is removed when the connection closes), `DELETE /v1/tunnels/{name}` (409 for
  tunnels from the file), `POST /v1/reload`, `GET /v1/events` (NDJSON stream).
- Reload (also on SIGHUP and `systemctl reload`): parse and validate the whole file first and keep the old set on
  error (frp); otherwise apply a diff by name — unchanged tunnels are not touched, changed ones are re-registered.
- Limits: `ReadHeaderTimeout`, 64 KiB request bodies.
- Socket hygiene (tailscale `safesocket`): on start, dial the existing socket; if it answers, exit with "already
  running", otherwise remove the stale file. Create the directory, listen, then chmod.
- Peer credentials (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS) are logged with every mutating call; they are
  the acting identity for the audit log of v0.3 (DESIGN.md §3.11).

### Who may use the socket

Adding a tunnel publishes a local service to the Internet, so write access is privileged. The system daemon runs as
its own user `porthole-client` (not the server's `porthole` user: a box may run both and the client must not read
the server's database). `/run/porthole` is 0750 and the socket 0660, both group `porthole-client`; users are
admitted with `usermod -aG porthole-client <user>` (the docker-group model). In user mode the directory is 0700.

### systemd

`deploy/porthole.service`: `Type=notify` (READY=1 is sent by hand on `$NOTIFY_SOCKET` once the socket is listening
and the file is loaded — not after the server connection, which is retried forever), `User=porthole-client`,
`RuntimeDirectory=porthole`, `RuntimeDirectoryMode=0750`, `ExecReload=porthole reload`, `Restart=on-failure`, and the
same hardening as `portholed.service` minus capabilities (the client binds nothing). The daemon never gives up on
the server (unlike `--max-initial-attempts` of the foreground CLI). A broken file at start is fatal (exit code 78,
`RestartPreventExitStatus=78`); a broken file on reload is not.

### Go packages

- `internal/client`: a `Manager` with a mutable tunnel set (`Add`, `Remove`, `Replace`, `Snapshot`, `Subscribe`)
  that re-registers the whole set after every reconnect and reports per-tunnel failures instead of ending; `Run`
  becomes a thin wrapper with the v0.1 semantics. The wire protocol does not change (`unregister` exists).
- `internal/clientconfig`: loading and validation of `tunnels.yaml`, conversion to `client.TunnelSpec`, diffing.
- `internal/localapi`: shared JSON types, the HTTP handler over a `Backend` interface, the client used by the CLI,
  socket listen/dial helpers, peer credentials, and sd_notify. The same types will back `--json` and the MCP server
  of v0.3, where `porthole mcp` becomes a thin adapter over `/v1`.

## Consequences

- No new dependencies (`golang.org/x/sys` becomes a direct one for peer credentials).
- A tunnel added with `--detach` is lost on a daemon restart by design; persistent tunnels go into the file.
- Windows and macOS get a user-mode daemon only; a Windows service (`x/sys/windows/svc`, named pipe with go-winio)
  and a launchd plist are deferred.

## Alternatives rejected

- Loopback TCP admin API (frp, ngrok): reachable by every local user and by browsers (DNS rebinding).
- One file with credentials and tunnels (ngrok, frp): the tunnels file could not be shared or committed.
- CLI that only works through the daemon (tailscale): breaks the v0.1 foreground workflow and Windows/macOS.
- File watcher for reload (cloudflared service mode): explicit reload is enough and predictable.
- Reusing the server's `porthole` user for the client daemon: needless access to the server's data.
