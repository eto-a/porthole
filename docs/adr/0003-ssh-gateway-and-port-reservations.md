# 0003. SSH gateway by name and persistent port reservations

- Status: accepted
- Date: 2026-10-01
- Issues: #5 (SSH gateway), #6 (private tunnels), #7 (port reservations)

## Context

The original use case is reaching an Ubuntu machine behind NAT through your own VPS. In v0.1 `porthole ssh` opens a
public TCP port (`ssh -p 20017 user@vps`): the number is hard to remember, it changes when the server restarts
(reservations are in memory), and the port is open to every scanner on the internet.

Requirements agreed with the user:

- The connecting machine runs plain OpenSSH and has **nothing** of porthole installed: no `porthole connect`, no
  ProxyCommand helper. Authentication to the target is the target's own sshd (password or key), end to end.
- Several concurrent sessions, users and target machines through one server.
- No private HTTP tunnels: a browser login flow (one-time link, cookie, logout, CSRF) is not worth it now. #6 shrinks
  to "the SSH gateway can require a token".

Options considered for "ssh by name":

| Option | Verdict |
|---|---|
| ProxyCommand `porthole connect %h` on the visitor (zrok private shares, `cloudflared access ssh`) | Rejected: needs software on the visitor |
| Route by SSH user name (`ssh home+artem@gw`), sshpiper model | Rejected (DESIGN §3.4): the gateway must terminate SSH, so it sees credentials and breaks end-to-end auth |
| Built-in SSH server used as a jump host, `ssh -J gw artem@home` (sish TCP aliases) | **Chosen**: stock OpenSSH, end-to-end auth |
| Stable per-tunnel TCP port only | Kept as well (#7), but a number is not a name |

`ssh -J` (ProxyJump, OpenSSH 7.3+) connects to the jump host and opens a `direct-tcpip` channel (RFC 4254 §7.2) to
`home:22`; the second SSH session runs inside that channel, so the jump host forwards ciphertext only.

## Decision

### SSH gateway (`portholed`)

- A new listener, `ssh_gateway.listen` (default `:2222`, like sish; port 22 of the VPS belongs to its own sshd).
  Disabled when the key is empty. Built on `golang.org/x/crypto/ssh` (BSD-3-Clause), which sish also uses.
- The gateway is not a shell: it accepts only `direct-tcpip` channels and refuses sessions, `exec`, `tcpip-forward`,
  agent and X11 forwarding. Logging in to the VPS through it is impossible.
- Target resolution from the `direct-tcpip` host: `<client>` means the `ssh` tunnel of client `<client>` (`home`);
  `<tunnel>-<client>` means that client's tunnel of kind `ssh` (`nas-home`). A trailing `.<domain>` is accepted and
  stripped, so `ssh -J gw artem@home.tun.example.com` also works. The requested port is ignored: the tunnel decides
  the local address. Unknown target → the channel is rejected with `ConnectionFailed`, the same reply for "no such
  machine" and "not allowed" (no enumeration).
- Each accepted channel becomes one data stream to the client over the existing yamux session, exactly like a TCP
  tunnel connection, so concurrent sessions, users and targets need no new machinery.
- Host key: ed25519, generated at first start into `<data_dir>/ssh_host_ed25519_key` (0600) and logged with its
  SHA256 fingerprint so the user can compare it on the first `ssh -J`. `portholed ssh-hostkey` prints the
  fingerprint.
- Gateway authentication (#6):
  - Public `ssh` tunnel (default): the gateway accepts SSH `none` auth, so the user sees only the target's own
    password or key prompt. Exposure equals today's public TCP port, but scanners must know a valid name.
  - Private tunnel (`porthole ssh --private`): the gateway requires `password` auth whose password is a porthole token
    belonging to the same client, or carrying the scope `connect:<client>`. The token is re-read from the store on
    every attempt (DESIGN §3.3). The user then enters the target password as usual.
  - Because SSH authenticates before the `direct-tcpip` request names a target, the gateway offers `none` and
    `password`; a `none` session may open channels only to public tunnels, a password session to the tunnels its
    token grants.
- Limits: handshake deadline 10 s; failed auth is rate limited per source IP with the existing handshake limiter;
  at most `ssh_gateway.max_conns_per_tunnel` concurrent channels per tunnel (default 256); idle connections without
  channels are closed after 60 s.

### Protocol and client

- New tunnel kind `ssh`: reachable only through the gateway, no public TCP listener. `Register` gains an optional
  `private` boolean; `Registered` echoes `private` and adds `ssh_jump` (`host:port` of the gateway) so the CLI can
  print the ready command.
- Safety against old servers: a server that does not know kind `ssh` answers `invalid_request` (unknown kind), and
  the CLI then falls back to v0.1 behaviour (a public TCP tunnel) with a warning; `--private` never falls back. A
  `Registered` without `private: true` for a private request is treated as a failure, since an old server would
  silently ignore the unknown field.
- `porthole ssh [--private] [--name N]` prints, for example:

  ```
  ssh -J tun.example.com:2222 <user>@home
  # or once in ~/.ssh/config:  Host home  /  ProxyJump tun.example.com:2222
  ```

  `porthole ssh --public-port` keeps the v0.1 public-port mode. In `tunnels.yaml`, `type: ssh` gains `private: true` and
  `public_port: true` (the `--public-port` mode); `remote_port` is only valid with `public_port: true`.

### Persistent port reservations (#7)

- Table `port_reservations(client TEXT, tunnel TEXT, port INTEGER NOT NULL UNIQUE, released_at INTEGER NULL,
  PRIMARY KEY (client, tunnel))`, an embedded migration in `internal/store`.
- A live tunnel has `released_at = NULL`. Closing it sets `released_at = now`; the row keeps the port for
  `(client, tunnel)` for 24 h (frp `server/ports.go`), then it is free. Expired rows are deleted lazily on allocation
  and at start.
- At start the server sets `released_at = now` on rows still `NULL` (the previous process died), so ports survive a
  crash or restart and the 24 h window starts then.
- `portholed token revoke` deletes the client's reservations; a changed `tcp_port_range` ignores rows outside it.

## Consequences

- One more public port (2222) on the server; it serves only forwarding, with no shell and no file access.
- Users keep stock OpenSSH and their own keys and passwords; porthole never sees SSH plaintext.
- Private gateway tunnels mean two password prompts (token, then the target account). Key-based gateway auth
  (registering visitor public keys) is possible later without protocol changes.
- New dependency: `golang.org/x/crypto/ssh`.
- HTTP tunnels stay public; DESIGN §3.4 is updated accordingly.
