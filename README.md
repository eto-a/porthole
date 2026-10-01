# porthole

**Self-hosted tunnels your AI agent can run.**

porthole is an open-source alternative to ngrok that runs on your own server. It publishes local web services over HTTPS, forwards TCP ports and lets you SSH into machines behind NAT by name. It has an [MCP](https://modelcontextprotocol.io) server built in, so Claude Code or any other agent can expose ports, inspect traffic and enrol new machines for you.

[![CI](https://github.com/eto-a/porthole/actions/workflows/ci.yml/badge.svg)](https://github.com/eto-a/porthole/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/eto-a/porthole?include_prereleases)](https://github.com/eto-a/porthole/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eto-a/porthole/badge)](https://scorecard.dev/viewer/?uri=github.com/eto-a/porthole)
[![Go Report Card](https://goreportcard.com/badge/github.com/eto-a/porthole)](https://goreportcard.com/report/github.com/eto-a/porthole)
[![Go version](https://img.shields.io/github/go-mod/go-version/eto-a/porthole)](go.mod)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Quick start](docs/quickstart.md) | [Install](docs/install.md) | [Agents](docs/agents.md) | [Server](docs/server.md) | [Client](docs/client.md) | [SSH by name](docs/ssh.md) | [Recipes](docs/recipes.md)

> **Alpha.** Only [preview releases](https://github.com/eto-a/porthole/releases) exist so far. The wire protocol, the configuration format and the CLI may still change. This README describes `main`; check the release notes of the version you install.

## Install with your agent

Paste this into Claude Code, or any coding agent that can run shell commands:

```text
Set up porthole for me: follow https://raw.githubusercontent.com/eto-a/porthole/main/docs/agent-install.md — ask me only what you can't find out yourself.
```

The agent asks for what it cannot detect (your VPS, your domain, which ports to open), installs the server and the clients, creates join links, checks that a tunnel works and, if you want, connects itself to porthole over MCP. The instructions tell it to ask before opening firewall ports and to keep tokens out of the chat. The full instructions it follows: [docs/agent-install.md](docs/agent-install.md).

## Install by hand

porthole has two parts: a server you set up once, and a client on every machine. There is no public instance and no third-party account: you own the server, the domain and the data. The whole path, step by step: [Quick start](docs/quickstart.md).

### Server (once, on a VPS)

Point `tun.example.com` and `*.tun.example.com` at the server's IP address, then:

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server
$ sudoedit /etc/porthole/portholed.yaml                 # set "domain: tun.example.com"
$ sudo systemctl enable --now portholed                 # open ports 80 and 443 first
$ sudo -u porthole portholed join create --name home    # a one-time link for the first machine
```

HTTPS certificates come from Let's Encrypt automatically, one per host name, with no DNS provider to configure. Packages, Docker and Dokploy: [Installation](docs/install.md#server-once-on-a-vps) and [Deploy](docs/deploy.md).

### Clients (on every machine)

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
$ porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...    # works once, valid for 15 minutes
$ porthole http 3000
connected as home
https://http-3000-home.tun.example.com -> 127.0.0.1:3000
```

More everyday commands:

```console
$ porthole http 192.168.1.10:3000 --name blog   # https://blog-home.tun.example.com
$ porthole tcp 5432                             # tcp://tun.example.com:<port from the range>
$ porthole ssh                                  # prints the ssh -J command for this machine
$ ssh -J tun.example.com:2222 alice@home        # from anywhere, with stock OpenSSH
```

For tunnels that survive reboots, list them in `tunnels.yaml` and run the client as a service; `porthole status` then shows the daemon's connection and tunnels (it needs the daemon). Windows and macOS archives, packages and the Docker sidecar: [Installation](docs/install.md#clients-on-every-machine); the daemon: [Client guide](docs/client.md#run-the-client-as-a-service).

## What your agent can do

```text
You:    Expose port 8080 on home
Agent:  request_tunnel {client: "home", kind: "http", local_addr: "8080"}
        -> https://http-8080-home.tun.example.com

You:    What hit my webhook in the last 10 minutes?
Agent:  query_requests {since: "10m"}

You:    Add my new laptop
Agent:  create_join_link {client: "laptop"}
        -> run on the laptop: porthole join https://tun.example.com/j/pj_...
```

Connect Claude Code to your server and to a machine:

```console
$ claude mcp add porthole -- ssh root@tun.example.com portholed mcp --read-only    # the server, over SSH
$ claude mcp add porthole-local -- porthole mcp                                    # this machine
```

The server can also be reached over HTTPS with a token; tools, scopes and toolsets are in [Agents](docs/agents.md). Without MCP, every command takes `--json` and has stable exit codes ([machine-readable output](docs/client.md#machine-readable-output---json)).

Safe to hand to an agent:

- **Scopes.** Every tool checks a scope; a token with only `admin:read` can look but not change anything, and `--read-only` registers no mutating tool at all.
- **Audit.** Every mutating call is logged with the token that made it, refusals included.
- **No secrets in the chat.** `create_join_link` returns a single-use, 15-minute link; the machine's permanent token never passes through the conversation. No tool returns a long-lived secret.
- **The machine has the last word.** The server can ask a client to open a tunnel only if the client's token allows it, and by default only for the machine's own ports. Other hosts on its LAN need to be listed in `allow_remote` on that machine.

## Features

- **HTTPS with automatic certificates.** One subdomain per HTTP or WebSocket tunnel; certificates from Let's Encrypt without a DNS provider ([TLS](docs/server.md#tls)).
- **SSH by name.** `ssh -J tun.example.com:2222 alice@home` with stock OpenSSH; `scp`, `sftp` and `rsync` work too. The gateway only forwards and never sees your password or key ([SSH by name](docs/ssh.md)).
- **TCP.** A database, a game server, anything, on a port from the server's range.
- **Tunnels that stay up.** A `tunnels.yaml` file and a systemd service for the client.
- **Traffic log and inspector.** Search requests, see what a webhook sent, replay it ([Request log](docs/server.md#request-log-and-inspection)).
- **Outbound-only client.** One TLS connection on port 443, so it works behind NAT and most corporate firewalls, and it reconnects by itself.
- **Signed releases.** Archives, deb and rpm packages and container images, with cosign signatures and build provenance ([verify a download](docs/install.md#verifying-a-download)).

## How it compares

Short answers, simplified from the public documentation of each tool; check it before you decide. No performance claims are made here.

- **Choose ngrok** if you want a hosted service and do not want to run a server at all. The server side is ngrok's.
- **Choose Cloudflare Tunnel (`cloudflared`)** if your domain is already on Cloudflare and you want its network in front. The server side is Cloudflare's, and for SSH its documentation has the connecting side run `cloudflared` or WARP.
- **Choose frp** if you want a self-hosted tunnel that already handles UDP and many proxy types, configured in `frps` and `frpc` files. porthole has no UDP yet.
- **Choose sish** if the machine behind NAT should run nothing but plain `ssh -R`.
- **Choose porthole** if you want to run the server yourself and let an agent manage it over MCP, with automatic HTTPS per tunnel, one-time join links and SSH by name for visitors who have only OpenSSH.

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

The client opens one outbound WebSocket-over-TLS session to `portholed` and multiplexes everything over it (yamux): one control stream for login, tunnel registration and heartbeats, and one data stream per visitor connection, opened by the server. For each data stream the client dials the local target and copies bytes both ways without interpreting them. HTTP routing by `Host`, TLS and WebSocket upgrades all live on the server. Details: [DESIGN.md](DESIGN.md) and the [wire protocol](docs/protocol.md).

## Documentation

- [Quick start](docs/quickstart.md): from an empty VPS to a public HTTPS address
- [Installation](docs/install.md): install script, packages, Docker, archives, verifying signatures, building from source
- [Install with an agent](docs/agent-install.md): the instructions your agent follows
- [Guides](docs/guides.md) and [Recipes](docs/recipes.md): webhooks, SSH behind NAT, a NAS on your LAN, a database
- [Agents](docs/agents.md): MCP servers, tools, toolsets and scopes
- [Server setup](docs/server.md) and [Deploy](docs/deploy.md): DNS, TLS, configuration, reverse proxies, Docker, Dokploy
- [Client guide](docs/client.md): join, `http`/`tcp`/`ssh`, the tunnels file, the daemon, `--json`
- [SSH by name](docs/ssh.md), [Troubleshooting](docs/troubleshooting.md), [FAQ](docs/faq.md)
- [DESIGN.md](DESIGN.md), [ADRs](docs/adr/) and example files: [portholed.example.yaml](deploy/portholed.example.yaml), [tunnels.example.yaml](deploy/tunnels.example.yaml), [Caddyfile.example](deploy/Caddyfile.example), [compose.yaml](deploy/compose.yaml)

## Status

Alpha. Roadmap, from [DESIGN.md](DESIGN.md#7-roadmap):

- **v0.2, install and forget:** install script, deb/rpm and Docker, client daemon, SSH gateway by name, private SSH tunnels, persisted port reservations.
- **v0.3, management by LLM agents:** admin API, MCP servers, join links, remote tunnel requests and a traffic inspector, instead of a web UI.
- **v0.4:** QUIC, UDP and more HTTP access control.

## Security

Tokens are 256-bit secrets stored only as hashes; authorization is re-checked on every tunnel registration, and revocation applies to live sessions. Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues.

## Contributing

Contributions are welcome; please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Commits need a Developer Certificate of Origin sign-off (`git commit -s`), and participants follow the [Code of Conduct](CODE_OF_CONDUCT.md). To build from source (Go 1.27 or newer): `make build`, see [Building from source](docs/install.md#building-from-source).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
