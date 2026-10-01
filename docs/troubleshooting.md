# Troubleshooting

Find your symptom, check the likely causes in order. The messages quoted here are the ones the programs print. On the
server the log is JSON on stderr (`journalctl -u portholed`); `portholed serve --log-level debug` shows more. On the
client add `-v` (`porthole -v http 3000`).

- [The certificate is not issued](#the-certificate-is-not-issued)
- [`cannot connect` and exit codes](#cannot-connect-and-exit-codes)
- [`name_taken`](#name_taken)
- [`session_replaced`: another porthole process logged in](#session_replaced-another-porthole-process-logged-in)
- [`ssh -J` fails: Permission denied, host key, `connect failed`](#ssh--j-fails-permission-denied-host-key-connect-failed)
- [`porthole join` is refused](#porthole-join-is-refused)
- [The daemon: permission denied on the socket](#the-daemon-permission-denied-on-the-socket)
- [Every visitor has the IP address of Traefik](#every-visitor-has-the-ip-address-of-traefik)
- [Other refusals of a tunnel](#other-refusals-of-a-tunnel)

## The certificate is not issued

The browser shows a certificate or connection error for `https://blog-home.tun.example.com`. With the default TLS mode
(`acme`) the server orders a certificate at the first connection to a name ([TLS](server.md#tls)). Check, in this order:

1. **DNS.** Both records must exist and point at the server: `tun.example.com` and the wildcard `*.tun.example.com`.
   `dig +short blog-home.tun.example.com` must print the address of the server. A wildcard does not cover the bare
   domain, so the apex needs its own record.
2. **Ports 80 and 443 from the internet.** The CA connects to both: HTTP-01 on port 80 and TLS-ALPN-01 on port 443. Check
   the firewall of the provider and of the host. A proxy that owns these ports must pass TLS through, see
   [Behind Traefik or Dokploy](server.md#behind-traefik-or-dokploy-tls-passthrough). `http_listen: ""` turns the port-80
   listener off, then only TLS-ALPN-01 works.
3. **The name is served at all.** A certificate is requested only for the control host and for the host of a live tunnel
   (or one whose client left a moment ago). For any other name the server does not contact the CA and logs
   `certificate refused` with the host name, either `name is not the control host or a tunnel host` or
   `no live tunnel with this label`. Start the tunnel first, and check the spelling: the host is
   `<tunnel>-<client>.<domain>`.
4. **Let's Encrypt limits.** 50 certificates per registered domain per week and 5 duplicates of one name per week.
   Every new tunnel name costs one certificate and a reused name costs nothing, so choose stable names and keep the
   data directory: it holds the certificates in `<data_dir>/certs`, which must be writable by the service user. The
   error from the CA is in the log (`component` is `acme`).
5. **Test with the staging CA.** Set `tls.acme.ca: https://acme-staging-v02.api.letsencrypt.org/directory` to experiment
   without touching the production limits. Its certificates are not trusted by browsers, so use `curl -k` to test.
   When you go live, switch the setting back and clear `<data_dir>/certs`.

## `cannot connect` and exit codes

While the client is retrying it prints:

```
cannot connect (attempt 1 of 5), retrying in 2s: ...
```

and after the last attempt:

```
could not connect to the server after 5 attempt(s): ...
the server host name does not resolve; check the server URL for typos; use --max-initial-attempts 0 to keep retrying
```

The second line depends on the cause. A host name that does not resolve: check the URL you gave to `porthole login` or
`porthole join` (the stored one is in the client config file). `the server certificate could not be verified`: the URL
must use the host name of the certificate, and the server needs a valid certificate (see above; a staging certificate is
not valid). Anything else: `check the server URL, that portholed is running, and that no firewall or proxy blocks the
connection`; the client needs an outbound connection to port 443. `--max-initial-attempts N` changes the limit and `0`
retries forever. Once a session was established, the client always reconnects.

The exit status tells scripts what happened:

| Status | Meaning |
|---|---|
| 0 | Success (also Ctrl-C of a foreground tunnel) |
| 1 | Any other failure |
| 2 | Usage error: unknown command, bad flag or argument |
| 3 | The server could not be reached (`--max-initial-attempts` reached, unknown host, TLS verification failed) |
| 4 | Authentication failed: `unauthorized`, `token_revoked`, `token_expired`; for `join`: a refused link |
| 5 | The server refused a tunnel: `name_taken`, `forbidden`, `limit_exceeded`, `port_unavailable`; also a `reload` in which a tunnel failed |
| 6 | The daemon is not running, or this user may not use its socket |
| 78 | Configuration problem that a restart cannot fix: missing or broken config or tunnels file, no credentials. The system service does not restart on it |

With `--json` a failure is `{"error":{"code":"...","message":"..."}}` on stdout ([codes](client.md#machine-readable-output---json)).
A token the server rejects while the daemon or the system service runs also exits with 78, so that the service does not
retry forever: ``token rejected by server (...); run `porthole login` with a valid token``, or `token expired (...)`. Get
a new token or link from the operator, run `porthole login` or `porthole join`, and restart the service.

## `name_taken`

`tunnel name already in use (name_taken: ...); choose another one with --name`. The server says either
`this session already has a tunnel with that name` or `hostname is already in use`.

- The same name is used twice by one machine: for example `blog` is in `tunnels.yaml` and you also ran
  `porthole http 3000 --name blog` while the daemon is running. List what is up with `porthole tunnels`; remove a
  runtime tunnel with `porthole close <name>`.
- The host name of an HTTP tunnel is `<tunnel>-<client>`, so two different pairs can produce the same host, for example
  the tunnel `a-b` of client `c` and the tunnel `a` of client `b-c`. Rename one of them.
- On `porthole join`: `a client with this name is already enrolled; ask the operator to revoke it first`. The operator
  revokes the old token (`portholed token revoke <name>`) or creates the link with another `--name`.

## `session_replaced`: another porthole process logged in

`another porthole process logged in with the same token (session_replaced: this client logged in again from another
connection; this session is closed); each machine needs its own token`.

A token is the identity of one machine and has one session. When the same token logs in a second time, the server closes
the older session, and the client that was replaced stops instead of fighting for it. Typical causes: the same token is
configured on two machines (create a join link for each: [Several machines](recipes.md#several-machines)), or a
standalone `porthole http ... --no-daemon` runs next to the daemon of the same machine. Use the daemon (leave out
`--no-daemon`), or stop it first.

## `ssh -J` fails: Permission denied, host key, `connect failed`

The first command to try is `ssh -v -J tun.example.com:2222 alice@home`: it shows which of the two SSH sessions, the one
to the gateway or the one to the target, fails. `-J` needs OpenSSH 7.3 or newer ([SSH by name](ssh.md)).

- **Permission denied (publickey, password) after the gateway.** The gateway has let you through, and the target's own
  sshd refuses you. The user name and key are those of the target machine (`alice@home`), not of the server: the
  gateway is not a shell and never sees your credentials. Check that `ssh alice@<address of the target>` works on its own
  network.
- **A password prompt for the jump host, or Permission denied before any prompt of the target.** The machine is private (`porthole ssh --private`). Select
  that mode with the user name `token`: `ssh -J token@tun.example.com:2222 alice@home` and give a porthole token as
  the password (the token of `home`, or one with the scope `connect:home`). A wrong or revoked token is refused (the server log has `ssh gateway login failed`); after repeated failures the rate limit per IP address applies (`ssh gateway login refused: too many failed attempts`), wait a little ([Private machines](ssh.md#public-and-private-machines)).
- **`connect failed`.** The gateway refuses the connection, and gives the same answer for an unknown and for a
  forbidden name, so that it does not reveal which machines exist. Is `porthole ssh` (or a `type: ssh` tunnel) running
  on the target? Is the name right: `home` for the tunnel `ssh`, `nas-home` for the tunnel `nas`? Is the machine connected (`porthole status` there; on the server the `list_clients` tool of the [operator agent](agents.md#tools))?
- **`ssh: connect to host tun.example.com port 2222: Connection refused` or a timeout.** The gateway is off or blocked:
  `ssh_gateway.listen` is set on the server and port 2222 is open ([SSH gateway](server.md#ssh-gateway)).
- **`WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED` for `[tun.example.com]:2222`.** The gateway key changed. It lives in
  `<data_dir>/ssh_host_ed25519_key`, so a lost data directory or a new server makes a new one. Compare the fingerprint
  with `portholed ssh-hostkey` on the server. If it is the one you expect, remove the old line:
  `ssh-keygen -R "[tun.example.com]:2222"`. The target has a host key of its own and is checked separately: a warning
  that names the target means another machine is now behind that name, or its sshd was reinstalled
  ([The gateway's host key](ssh.md#the-gateways-host-key)).

## `porthole join` is refused

The server's message says why, and the exit status is 4 (a refused link), 5 (`name_taken`) or 3 (the server cannot be
reached):

| Code | Message | What to do |
|---|---|---|
| `join_code_used` | `this join link was already used; ask for a new one` | A link works once. Ask for a new one. If you did not use it yourself, treat the link as leaked |
| `join_code_expired` | `this join link has expired; ask for a new one` | The default lifetime is 15 minutes; the operator can pass `--ttl` (up to `7d`) |
| `join_code_revoked` | `this join link was revoked; ask for a new one` | The operator ran `portholed join revoke` |
| `invalid_code` | `unknown or wrong join code` | The link was cut or mangled when copying (a terminal wraps long lines: copy it as one line and put it in quotes). Or the link comes from another server |
| `name_taken` | `a client with this name is already enrolled; ask the operator to revoke it first` | See [`name_taken`](#name_taken) |

The operator makes a new link with `sudo -u porthole portholed join create --name home`; the command fails while an
active token has that name, so revoke it first when the machine is re-enrolled (`portholed token revoke home`). Opening
the link in a browser only shows the command and does not use it up. The link contains the server's address from
`server_url` or `<public_scheme>://<domain>` ([Join links](server.md#join-links)); if the address is wrong, set
`server_url` or give the bare code and the address: `porthole join pj_... --server https://tun.example.com`.

## The daemon: permission denied on the socket

```
permission denied on the porthole daemon socket /run/porthole/porthole.sock: add your user to the group that owns it
(for the system daemon: `sudo usermod -aG porthole-client $USER`, then log in again), or use --no-daemon to run in this
process with your own token
```

The system daemon runs as the user `porthole-client`, and its socket is for root and the members of the group of that
name. Add yourself, then log in again (a new login session is needed for the group to apply):

```console
$ sudo usermod -aG porthole-client "$USER"
$ porthole status
```

Treat the group like the `docker` group: whoever can use the socket can publish local services to the internet. The
exit status is 6. If the message is instead that no daemon is running, check `systemctl status porthole` and
`journalctl -u porthole`; a broken configuration or tunnels file stops the service for good (status 78) instead of
restarting it in a loop. `--no-daemon` runs the tunnel in the current process with your own credentials, but
see [`session_replaced`](#session_replaced-another-porthole-process-logged-in) if the daemon uses the same token.

## Every visitor has the IP address of Traefik

Behind Traefik or Dokploy with TLS passthrough every connection reaches `portholed` from the proxy, and there is no
`X-Forwarded-For` because the proxy never reads the encrypted HTTP. The request log, the audit log and the per-address
limits then show one address. Use the PROXY protocol ([Why the PROXY protocol](deploy.md#why-the-proxy-protocol)):

- Traefik: the label `traefik.tcp.services.<name>.loadbalancer.proxyProtocol.version=2` on the TCP service (it is in
  [deploy/dokploy-compose.yaml](../deploy/dokploy-compose.yaml)).
- `portholed`: `proxy_protocol: true` and `trusted_proxies` with the address range of the Traefik network, for example
  `PORTHOLED_PROXY_PROTOCOL=true` and `PORTHOLED_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12`. Narrow the range to the
  subnet from `docker network inspect dokploy-network`.

If connections stop working after you turn it on, the two sides disagree: a peer in `trusted_proxies` must send a header
and is refused without one, and a peer outside the list must not send one. So the label is missing, or the subnet of
the proxy is not in the list. The header must arrive within 5 seconds. The plain HTTP listener (port 80: challenge and
redirect) still sees Traefik's address unless `proxy_protocol_http` is set and the proxy sends the header there; it
serves no tunnel traffic. Do not turn on `trust_proxy_headers` for passthrough: it is for a proxy that terminates TLS
([Behind a reverse proxy](server.md#behind-a-reverse-proxy)).

## Other refusals of a tunnel

| Message | Cause |
|---|---|
| `server refused the tunnel (forbidden: token lacks scope tunnel:http); ...` | The token lacks the scope for this kind of tunnel (`tunnel:http`, `tunnel:tcp`); see `portholed token list` |
| `tunnel limit reached (N)` (`limit_exceeded`) | The machine has the maximum number of simultaneous tunnels: `max_tunnels_per_client` or the `--max-tunnels` of its token |
| `requested port is not available (port_unavailable: ...); try another --remote-port or omit it` | The server says `requested port is outside the allowed range`, `requested port is not available` or `no free port in the configured range`: the port is outside `tcp_port_range`, in use, or reserved for another client ([reservations](server.md#tcp-ports-and-reservations)) |
| `forbidden: this server does not allow request inspection (traffic.allow_inspect is false)` | `--inspect` on a server that forbids it; start the tunnel without it |
| A replayed request gets `401` | `Authorization` and cookies are stored as `REDACTED` and are not replayed ([inspection](client.md#expose-a-service)) |
