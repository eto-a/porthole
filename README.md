# porthole

**Self-hosted tunnels built for LLM agents: your agent exposes ports, opens SSH to machines behind NAT, inspects
traffic and onboards new machines, on your own server.** An open-source alternative to ngrok that Claude Code (or any
[MCP](https://modelcontextprotocol.io) client) can drive.

[![CI](https://github.com/eto-a/porthole/actions/workflows/ci.yml/badge.svg)](https://github.com/eto-a/porthole/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/eto-a/porthole?include_prereleases)](https://github.com/eto-a/porthole/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eto-a/porthole/badge)](https://scorecard.dev/viewer/?uri=github.com/eto-a/porthole)
[![Go Report Card](https://goreportcard.com/badge/github.com/eto-a/porthole)](https://goreportcard.com/report/github.com/eto-a/porthole)
[![Go version](https://img.shields.io/github/go-mod/go-version/eto-a/porthole)](go.mod)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Quickstart](docs/quickstart.md) | [Agents](docs/agents.md) | [Install](docs/install.md) | [Server](docs/server.md) |
[Client](docs/client.md) | [SSH by name](docs/ssh.md) | [Recipes](docs/recipes.md) | [Releases](https://github.com/eto-a/porthole/releases)

## What your agent can do

```text
You:    Expose port 8080 on home
Agent:  request_tunnel {client: "home", kind: "http", local_addr: "8080"}
        -> https://http-8080-home.tun.example.com

You:    What hit my webhook in the last 10 minutes?
Agent:  query_requests {since: "10m"}      (headers and bodies if the tunnel runs with --inspect)

You:    Add my new laptop
Agent:  create_join_link {client: "laptop"}
        -> run on the laptop: porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...
```

Connect Claude Code to your server and to a machine (details and the full tool list: [Agents](docs/agents.md)):

```console
$ sudo -u porthole portholed token create --name ops-agent --scopes admin:read,admin:tunnels,admin:remote,admin:tokens   # on the server
$ claude mcp add --transport http porthole https://tun.example.com/_porthole/mcp --header "Authorization: Bearer ph_..."
$ claude mcp add porthole-local -- porthole mcp                                                  # on a client machine
```

### Safe to hand to an agent

- **Scopes and toolsets.** Every tool checks a scope (`admin:read`, `admin:tunnels`, `admin:remote`, ...); an agent that
  should only look around gets a token with `admin:read`. `--read-only` registers no mutating tool at all.
- **Audit.** Every mutating call is written to the audit log with the token that made it, including refusals.
- **Join links, not secrets.** `create_join_link` returns a single-use, 15-minute link; the permanent token goes
  straight to the new machine and never passes through the conversation. No tool returns a long-lived secret.
- **The machine has the last word.** When the server asks a client to open a tunnel, it only goes through if the client's
  token allows remote control and the machine's own policy accepts the target. By default that means ports of the
  machine itself (loopback); other hosts on its LAN only if you list them in `allow_remote`.
- **No MCP? Use the CLI.** `--json` makes every command print JSON (JSON Lines for long-running ones) and use stable exit
  codes, so any agent can script it: `porthole http 8080 --detach --json`. See
  [machine-readable output](docs/client.md#machine-readable-output---json).

## And the tunnels themselves

- **HTTPS with automatic certificates.** One subdomain per HTTP(S) or WebSocket tunnel; the server gets Let's Encrypt
  certificates itself, no DNS provider needed ([TLS](docs/server.md#tls)).
- **SSH by name.** `ssh -J tun.example.com:2222 alice@home` with stock OpenSSH and nothing installed on the machine you
  connect from; `scp`, `sftp` and `rsync` work too. The gateway only forwards and never sees your password or key
  ([SSH by name](docs/ssh.md)).
- **TCP.** A database, a game server, anything, on a port of the server's range.
- **Service and daemon.** List tunnels in `tunnels.yaml`, run the client as a systemd service, and they survive reboots.
- **Traffic log and inspector.** Search requests, see what a webhook sent, replay it ([Request log](docs/server.md#request-log-and-inspection)).
- **Outbound-only client.** One TLS connection on port 443, so it works behind NAT and most corporate firewalls and
  reconnects automatically. Stable addresses, tokens with expiry and scopes, signed releases ([verify a download](docs/install.md#verifying-a-download)).

> **Status: alpha.** Only [preview releases](https://github.com/eto-a/porthole/releases) exist so far. The wire
> protocol, the configuration format and the CLI may still change before the first stable release. Do not rely on it
> for anything you cannot afford to break. This README describes `main`; check the release notes of the version you
> install.

## Install

porthole has two parts: a server you set up once, and a client on every machine. No public instance, no account with a
third party: you own the server, the domain and the data. A first run from scratch: [Quickstart](docs/quickstart.md).

### Server (once, on a VPS)

1. **DNS.** Point the domain and a wildcard at the server's IP address:
   `tun.example.com. A 203.0.113.10` and `*.tun.example.com. A 203.0.113.10`.
2. **Install**, with the script, a Docker image or Dokploy ([all options](docs/install.md#server-once-on-a-vps)):

   ```console
   $ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server
   ```

   With Docker see [Docker](docs/install.md#docker) and [deploy/compose.yaml](deploy/compose.yaml); on Dokploy paste
   [deploy/dokploy-compose.yaml](deploy/dokploy-compose.yaml) as a Compose service ([deploy guide](docs/deploy.md)).
3. **Configure and start.** Set `domain: tun.example.com` in `/etc/porthole/portholed.yaml`, open ports 80 and 443 (and
   the TCP range and SSH port if you use them), then `sudo systemctl enable --now portholed`. HTTPS certificates are
   obtained automatically, per host name, from Let's Encrypt. Other modes: [TLS](docs/server.md#tls).
4. **Create a join link** for the first machine:

   ```console
   $ sudo -u porthole portholed join create --name home
   ```

### Clients (on every machine)

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
$ porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_....    # works once, valid for 15 minutes
$ porthole http 3000
connected as home
https://http-3000-home.tun.example.com -> 127.0.0.1:3000
```

For tunnels that stay up, list them in `tunnels.yaml` and run the client as a service:

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

Packages, Docker sidecar, Windows and macOS archives: [Installation](docs/install.md#clients-on-every-machine). More
on the daemon, user units and `--detach`: [Client guide](docs/client.md).

### Everyday commands

```console
$ porthole http 192.168.1.10:3000 --name blog   # https://blog-home.tun.example.com
$ porthole tcp 5432                             # tcp://tun.example.com:<port from the range>
$ porthole ssh                                  # prints the ssh -J command for this machine
$ ssh -J tun.example.com:2222 alice@home        # from anywhere; private variant: porthole ssh --private
```

## How it compares

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

- [Quickstart](docs/quickstart.md) and [Recipes](docs/recipes.md): first run, then ready commands for real services
- [Guides](docs/guides.md): expose localhost, webhooks, SSH behind NAT/CGNAT, a NAS on your LAN, let an agent do it
- [Agents](docs/agents.md): MCP servers for Claude Code and other agents, tools, toolsets, scopes
- [Installation](docs/install.md): server and clients, packages, Docker, archives, verifying signatures, building from source
- [Deploy](docs/deploy.md): VPS, Docker Compose and Dokploy step by step; [Troubleshooting](docs/troubleshooting.md); [FAQ](docs/faq.md)
- [Server setup](docs/server.md): DNS, TLS, configuration, reverse proxy, SSH gateway, tokens, ports
- [Client guide](docs/client.md): join, `http`/`tcp`/`ssh`, tunnels file, daemon, `--json`
- [SSH by name](docs/ssh.md): `ssh -J`, public and private machines, `~/.ssh/config`, host key
- [DESIGN.md](DESIGN.md): architecture and reasoning; [docs/protocol.md](docs/protocol.md): wire format;
  [docs/adr/](docs/adr/): individual decisions
- Examples: [portholed.example.yaml](deploy/portholed.example.yaml), [tunnels.example.yaml](deploy/tunnels.example.yaml),
  [Caddyfile.example](deploy/Caddyfile.example), [compose.yaml](deploy/compose.yaml)

## Status

Alpha. Roadmap, from [DESIGN.md](DESIGN.md#7-roadmap): v0.2 "install and forget" (install script, deb/rpm and Docker,
client daemon, SSH gateway by name, private SSH tunnels, persisted port reservations); v0.3 management by LLM agents
(admin API, MCP servers, join links, remote tunnel requests, traffic inspector) instead of a web UI; v0.4 QUIC, UDP
and more HTTP access control.

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
