# porthole

[![CI](https://github.com/eto-a/porthole/actions/workflows/ci.yml/badge.svg)](https://github.com/eto-a/porthole/actions/workflows/ci.yml)

**porthole** is a self-hosted, open-source alternative to ngrok. You run one server, `portholed`, on a machine with a
public IP address and a domain. On any machine behind NAT you run the client, `porthole`, and expose a local service
with a single command:

```console
$ porthole login https://tun.example.com ph_3kq9w2m1z8xa_....     # once per machine
$ porthole http 8080
https://http-8080-home.tun.example.com  ->  localhost:8080
$ porthole tcp 7575
tcp://tun.example.com:20017  ->  localhost:7575
$ porthole ssh
ssh -p 20018 <user>@tun.example.com  ->  localhost:22
```

> **Status: early development, v0.1 in progress.** The wire protocol, the configuration format and the CLI may
> still change before the first release. Do not rely on it for anything you cannot afford to break.

## What makes it different

- **Self-hosted.** There is no public instance and none is planned: you own the server, the domain and the data.
- **Client-driven.** Tunnels are configured on the client (`porthole http 8080`); the server allocates the public
  address and returns it. The server operator only issues tokens.
- **Token-based access.** Tokens are created, listed and revoked on the server, can expire, and carry scopes and
  tunnel limits. A token is a client identity: every client sees and manages only its own tunnels and names.
- **Outbound-only client.** The client opens one TLS connection to the server on port 443, so it works from behind
  NAT and most corporate firewalls.
- **HTTP(S), WebSocket, TCP and SSH.** HTTP tunnels get a subdomain; TCP tunnels get a port from a configured range;
  `porthole ssh` is a TCP tunnel to your local sshd that prints a ready-to-use `ssh` command.
- **Single static binary per side**, no CGO, trivial to deploy with systemd or Docker.

Roadmap (not in v0.1): UDP tunnels, an SSH gateway (`ssh home.ssh.tun.example.com`), QUIC transport, private
tunnels, a client daemon, automatic certificates. See the roadmap in [DESIGN.md](DESIGN.md#7-roadmap).

## Quickstart

### 1. Server

You need a machine with a public IP address and a domain you control. The examples use `tun.example.com`.

**DNS.** Point the domain and a wildcard at the server's IP address:

```
tun.example.com.     A   203.0.113.10
*.tun.example.com.   A   203.0.113.10
```

**TLS.** HTTP tunnels live on `https://<name>.tun.example.com`, so you need a wildcard certificate (a wildcard does
not cover the apex, so request both names). With certbot and a DNS-01 plugin, for example Cloudflare:

```console
$ certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
    -d tun.example.com -d '*.tun.example.com'
```

Certificates are read from files; make sure your renewal hook restarts `portholed`. Alternatively, run `portholed`
in plain HTTP behind a reverse proxy that terminates TLS: see
[deploy/Caddyfile.example](deploy/Caddyfile.example) and set `trust_proxy_headers: true`.

**Configuration** (`/etc/porthole/portholed.yaml`; the full annotated example is
[deploy/portholed.example.yaml](deploy/portholed.example.yaml)):

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

Unknown keys are rejected. Every setting can also be given as a `PORTHOLED_*` environment variable, for example
`PORTHOLED_DOMAIN` or `PORTHOLED_TCP_PORT_RANGE`.

**Firewall.** Open TCP 443 (control connections and HTTP tunnels) and the TCP port range for TCP and SSH tunnels.

**Run it.**

```console
$ portholed serve --config /etc/porthole/portholed.yaml
```

For production use the systemd unit in [deploy/portholed.service](deploy/portholed.service) or the container files
in [deploy/](deploy/).

**Create a token** (one per client machine; the name becomes the client name in the public URLs):

```console
$ portholed token create --name home
```

The token is shown once (the server stores only a hash), together with a ready-to-use `porthole login` command. The
`token` commands read the same configuration and database as `serve` (use `--config` if it is not at
`/etc/porthole/portholed.yaml`). Token names are 1-32 characters of `a-z`, `0-9` and `-`. More options:

```console
$ portholed token create --name office-nas --expires 30d --scopes tunnel:http,tunnel:tcp --max-tunnels 5
$ portholed token list            # --all includes revoked tokens, --json prints a JSON array
$ portholed token revoke home     # by id or name; takes effect on live sessions
```

### 2. Client

```console
$ porthole login https://tun.example.com ph_...      # stores the server and token in your user config
$ porthole login https://tun.example.com ph_... --check   # also connects to the server and verifies the token

$ porthole http 8080                  # https://http-8080-home.tun.example.com
$ porthole http 8080 --name blog      # https://blog-home.tun.example.com
$ porthole tcp 7575                   # tcp://tun.example.com:<port from the range>
$ porthole tcp 192.168.1.5:7575 --remote-port 20017
$ porthole ssh                        # TCP tunnel to localhost:22
```

Commands run in the foreground, print the public address, and reconnect automatically if the connection drops.

CLI summary:

| Command | Purpose |
|---|---|
| `portholed serve [--config] [--log-level]` | Run the server |
| `portholed token create --name N [--expires 30d] [--scopes ...] [--max-tunnels N]` | Create a token |
| `portholed token list [--all] [--json]` | List tokens |
| `portholed token revoke <id\|name>` | Revoke a token |
| `portholed version` | Print the version |
| `porthole login <url> <token> [--check]` | Store credentials |
| `porthole http <port\|host:port> [--name]` | Expose a local web service |
| `porthole tcp <port\|host:port> [--name] [--remote-port]` | Expose a local TCP service |
| `porthole ssh [--local-port 22] [--user] [--name]` | Expose the local SSH server |
| `porthole version` | Print the version |

## How it works

The client opens one outbound WebSocket-over-TLS session to `portholed` and multiplexes everything over it
(yamux). Inside the session there is one control stream (login, tunnel registration, heartbeats) and one data
stream per visitor connection, opened by the server. The client never interprets proxied bytes: for each data
stream it dials the local target and copies bytes both ways. HTTP routing by `Host`, TLS and WebSocket upgrades
all live on the server.

See [DESIGN.md](DESIGN.md) for the design and the reasoning behind it, [docs/protocol.md](docs/protocol.md) for the
wire format and [docs/adr/](docs/adr/) for individual decisions.

## Security

Tokens are 256-bit secrets stored only as hashes; authorization is re-checked on every tunnel registration and
revocation applies to live sessions. Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), not in public issues.

## Building from source

Requires Go 1.27 or newer.

```console
$ go build ./cmd/...          # binaries in the current directory
$ make build                  # static, stripped, versioned binaries in ./bin
$ make lint test              # needs golangci-lint v2
```

## Contributing

Contributions are welcome; please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Contributions require a
Developer Certificate of Origin sign-off (`git commit -s`). By participating you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
