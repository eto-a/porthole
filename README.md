# porthole

**A self-hosted, open-source alternative to ngrok: expose a service behind NAT through your own server, and reach your
machines over SSH by name.**

[![CI](https://github.com/eto-a/porthole/actions/workflows/ci.yml/badge.svg)](https://github.com/eto-a/porthole/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/eto-a/porthole?include_prereleases)](https://github.com/eto-a/porthole/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eto-a/porthole/badge)](https://scorecard.dev/viewer/?uri=github.com/eto-a/porthole)
[![Go Report Card](https://goreportcard.com/badge/github.com/eto-a/porthole)](https://goreportcard.com/report/github.com/eto-a/porthole)
[![Go version](https://img.shields.io/github/go-mod/go-version/eto-a/porthole)](go.mod)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Install](docs/install.md) | [Server](docs/server.md) | [Client](docs/client.md) | [SSH by name](docs/ssh.md) |
[Design](DESIGN.md) | [Releases](https://github.com/eto-a/porthole/releases)

You run one server, `portholed`, on a machine with a public IP address and a domain. On any machine behind NAT you run
the client, `porthole`. No public instance, no usage limits, no account with a third party: you own the server, the
domain and the data. The headline use case is `ssh -J tun.example.com:2222 alice@home` with stock OpenSSH and nothing
installed on the machine you connect from. Management of the server by LLM agents (admin API and MCP server) is next on
the [roadmap](#status).

> **Status: alpha.** Only [preview releases](https://github.com/eto-a/porthole/releases) exist so far. The wire
> protocol, the configuration format and the CLI may still change before the first stable release. Do not rely on it
> for anything you cannot afford to break. This README describes `main`; check the release notes of the version you
> install.

## Quick start

```console
# On the server (public IP, domain and wildcard DNS record, TLS certificate: see docs/server.md)
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server
$ sudo -u porthole portholed join create --name home       # prints a one-time `porthole join` command

# On your machine, behind NAT
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
$ porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_....    # works once, valid for 15 minutes
$ porthole http 3000
connected as home
https://http-3000-home.tun.example.com -> 127.0.0.1:3000
```

The first command only installs the server: edit `/etc/porthole/portholed.yaml` and start the service as described in
[Server setup](docs/server.md) before creating the join link (it needs the running server). A join link hands the
machine its own token without anyone copying a secret; `portholed token create` and `porthole login` remain for scripted setups.

## Use cases

**Publish a web application** (HTTPS and WebSocket, one subdomain per tunnel):

```console
$ porthole http 8080                       # https://http-8080-home.tun.example.com
$ porthole http 192.168.1.10:3000 --name blog   # https://blog-home.tun.example.com
```

**SSH to a home machine behind NAT, by name.** On the machine (it needs an sshd), run `porthole ssh`; it prints the
command. Anywhere else, with plain OpenSSH:

```console
$ ssh -J tun.example.com:2222 alice@home
```

or once in `~/.ssh/config`, then just `ssh home` (also `scp`, `sftp`, `rsync`):

```
Host home
    HostName home
    User alice
    ProxyJump tun.example.com:2222
```

The gateway only forwards, never gives a shell on the server, and never sees your password or key. Compare its host
key fingerprint (`portholed ssh-hostkey`) on the first connection. Details: [SSH by name](docs/ssh.md).

**Private SSH**: `porthole ssh --private` makes the gateway ask for a porthole token before it opens the tunnel; you
select this with the user name `token`:

```console
$ ssh -J token@tun.example.com:2222 alice@home
```

**A TCP service** (database, game server, anything), on a port of the server's range:

```console
$ porthole tcp 5432                        # tcp://tun.example.com:<port from the range>
$ porthole tcp nas.local:5432 --remote-port 20017
```

**Several tunnels that survive reboots.** List them in `tunnels.yaml` and run the client as a service:

```yaml
version: 1
tunnels:
  blog: {type: http, addr: 3000}
  db:   {type: tcp, addr: "nas.local:5432"}
  ssh:  {type: ssh}
```

```console
$ sudo systemctl enable --now porthole     # deb/rpm package; or `porthole start` in the foreground
$ porthole status
```

See the [Client guide](docs/client.md) for the daemon, user units and `--detach`.

## Features

| | |
|---|---|
| **Self-hosted** | One static binary per side, no CGO; systemd units, deb/rpm packages and distroless Docker images ([install](docs/install.md)) |
| **Client-driven** | Tunnels are configured on the client; the server allocates the address and only issues tokens |
| **Outbound-only client** | One TLS connection to the server on port 443, so it works behind NAT and most corporate firewalls; reconnects automatically |
| **Protocols** | HTTP(S) and WebSocket (subdomain per tunnel), TCP (port from a configured range), SSH (by name through the gateway) |
| **Tokens** | Created, listed and revoked on the server; they can expire and carry scopes and tunnel limits; a token is a client identity, and each client sees only its own tunnels and names |
| **Stable addresses** | HTTP names are derived from the tunnel name; TCP ports stay reserved for a client and tunnel name for 24 hours, also across server restarts |
| **TLS** | From certificate files (renewals picked up without a restart) or behind a reverse proxy such as Caddy ([server setup](docs/server.md)) |
| **Agent-managed** | MCP servers for LLM agents: an operator endpoint on the server (`/_porthole/mcp`, bearer token with scopes, toolsets, `--read-only`, audit log; list and search clients, tunnels and traffic, replay recorded requests, open a tunnel on a connected client on request, create single-use join links) and `porthole mcp` for opening tunnels on a machine ([agents](docs/agents.md)) |
| **Supply chain** | Signed releases (cosign), build provenance attestations, SBOMs ([verify a download](docs/install.md#verifying-a-download)) |

### How it compares

| | porthole | ngrok | frp | cloudflared | sish |
|---|---|---|---|---|---|
| You run the server | yes | no, hosted service | yes | no, Cloudflare network | yes |
| On the machine behind NAT | `porthole` | `ngrok` agent | `frpc` | `cloudflared` | plain `ssh -R` |
| SSH by name with only OpenSSH on the connecting side | yes (`ssh -J`) | see its docs | see its docs | needs `cloudflared` or WARP on the visitor | yes (TCP aliases) |

Statements about other tools come from their public documentation and are simplified; check them before deciding. No
performance claims are made here.

## How it works

```
                      HTTPS / TCP / ssh -J
   visitors ------------------------------->  portholed  <======================  porthole
 (browser, ssh, ...)    tun.example.com       (your VPS)    one outbound TLS       (behind NAT)
                                                            session, many streams       |
                                                                                        +--> 127.0.0.1:3000
                                                                                        +--> nas.local:5432
                                                                                        +--> 127.0.0.1:22
```

The client opens one outbound WebSocket-over-TLS session to `portholed` and multiplexes everything over it (yamux).
Inside the session there is one control stream (login, tunnel registration, heartbeats) and one data stream per visitor
connection, opened by the server. The client never interprets proxied bytes: for each data stream it dials the local
target and copies bytes both ways. HTTP routing by `Host`, TLS and WebSocket upgrades all live on the server.

## Documentation

- [Installation](docs/install.md): install script, packages, Docker, archives, verifying signatures, building from source
- [Server setup](docs/server.md): DNS, TLS, configuration, reverse proxy, Docker Compose, SSH gateway, tokens, ports
- [Client guide](docs/client.md): login, `http`/`tcp`/`ssh`, tunnels file, daemon and services
- [SSH by name](docs/ssh.md): `ssh -J`, public and private machines, `~/.ssh/config`, host key
- [Agents](docs/agents.md): MCP servers for Claude Code and other agents, tools, toolsets, scopes
- [DESIGN.md](DESIGN.md): architecture and reasoning; [docs/protocol.md](docs/protocol.md): wire format;
  [docs/adr/](docs/adr/): individual decisions
- Examples: [portholed.example.yaml](deploy/portholed.example.yaml), [tunnels.example.yaml](deploy/tunnels.example.yaml),
  [Caddyfile.example](deploy/Caddyfile.example), [compose.yaml](deploy/compose.yaml)

## Status

Alpha. Roadmap, from [DESIGN.md](DESIGN.md#7-roadmap): v0.2 "install and forget" (install script, deb/rpm and Docker,
client daemon, SSH gateway by name, private SSH tunnels, persisted port reservations); v0.3 management by LLM agents
(admin API and MCP server) instead of a web UI; v0.4 QUIC, UDP and more HTTP access control.

## Security

Tokens are 256-bit secrets stored only as hashes; authorization is re-checked on every tunnel registration and
revocation applies to live sessions. Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), not in public issues.

## Contributing

Contributions are welcome; please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Contributions require a
Developer Certificate of Origin sign-off (`git commit -s`). By participating you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). To build from source (Go 1.27 or newer): `make build`, see
[Installation](docs/install.md#building-from-source).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
