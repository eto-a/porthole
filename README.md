# porthole

[![CI](https://github.com/eto-a/porthole/actions/workflows/ci.yml/badge.svg)](https://github.com/eto-a/porthole/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eto-a/porthole/badge)](https://scorecard.dev/viewer/?uri=github.com/eto-a/porthole)
[![Go Report Card](https://goreportcard.com/badge/github.com/eto-a/porthole)](https://goreportcard.com/report/github.com/eto-a/porthole)
[![Go version](https://img.shields.io/github/go-mod/go-version/eto-a/porthole)](go.mod)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**porthole** is a self-hosted, open-source alternative to ngrok. You run one server, `portholed`, on a machine with a
public IP address and a domain. On any machine behind NAT you run the client, `porthole`, and expose a local service
with a single command:

```console
$ porthole login https://tun.example.com ph_3kq9w2m1z8xa_....     # once per machine
$ porthole http 8080
connected as home
https://http-8080-home.tun.example.com -> 127.0.0.1:8080
$ porthole tcp 7575
connected as home
tcp://tun.example.com:20017 -> 127.0.0.1:7575
$ porthole ssh
connected as home
tcp://tun.example.com:20018 -> 127.0.0.1:22
  ssh -p 20018 alice@tun.example.com
```

> **Status: alpha.** The first preview, [v0.1.0-alpha.1](https://github.com/eto-a/porthole/releases), is out. The
> wire protocol, the configuration format and the CLI may still change before v0.1.0. Do not rely on it for anything
> you cannot afford to break.

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

Roadmap: v0.2 one-line install, deb/rpm and Docker, a client daemon, an SSH gateway (`ssh home.tun.example.com`) and
private tunnels; v0.3 management by LLM agents (admin API + MCP server) instead of a web UI; v0.4 QUIC and UDP. See the roadmap in [DESIGN.md](DESIGN.md#7-roadmap).

## Installation

You do not need to build anything. Use the install script, a Linux package, a container image, or an archive; all of
them come from the [GitHub releases](https://github.com/eto-a/porthole/releases) (Linux and macOS on amd64 and arm64;
Windows has archives only).

> Packages and container images are produced by the release workflow, so they exist for releases made after
> v0.1.0-alpha.1. That release has archives only; the install script falls back to them.

### Install script (Linux and macOS)

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh                   # client: porthole
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server    # server: portholed
```

The script detects your OS and CPU, downloads the release, checks its SHA-256 against `checksums.txt` and installs it,
using `sudo` only when needed. If [cosign](https://docs.sigstore.dev) is installed it also verifies the signature of
`checksums.txt`. Nothing is installed when a check fails. To read it first, download it and run it:
`curl -fsSL -o install.sh https://raw.githubusercontent.com/eto-a/porthole/main/install.sh`, then `sh install.sh --help`.

| Option | Meaning |
|---|---|
| `--server` | Install `portholed` instead of `porthole`. On Debian/Ubuntu and RHEL/Fedora (as root or with sudo) this installs the `.deb`/`.rpm`, including the systemd unit and the `porthole` user; elsewhere only the binary |
| `--version v0.1.0` | Install this release. Default: the latest stable release; while there is no stable release yet, the newest pre-release (the script says so) |
| `--prerelease` | Take the newest release including pre-releases, even if a stable one exists |
| `--bin-dir DIR` | Where to put the binary. Default `/usr/local/bin`, or `~/.local/bin` if that is not writable |
| `--archive` | With `--server`, install the binary from the archive even where a package could be used |
| `--no-verify-signature` | Skip the cosign check even if cosign is installed (SHA-256 is always checked) |
| `--dry-run` | Print what would be done and exit |

Without `--version` the script asks the GitHub API for the latest release (60 requests per hour per IP address); with
`--version` it makes no API call. Without cosign, the SHA-256 check only protects against a corrupted download, not against
a tampered release: see [Verifying a download](#verifying-a-download).

### Packages (Debian, Ubuntu, Fedora, RHEL and derivatives)

Download the package for your CPU from [Releases](https://github.com/eto-a/porthole/releases) (`portholed_*` is the
server, `porthole_*` the client; amd64 and arm64) and install it:

```console
$ sudo apt install ./portholed_<version>_linux_amd64.deb        # Debian, Ubuntu
$ sudo dnf install ./portholed_<version>_linux_amd64.rpm        # Fedora, RHEL, Rocky, Alma
$ sudo apt install ./porthole_<version>_linux_amd64.deb         # client
```

The server package installs the binary in `/usr/bin`, the systemd unit `portholed.service`, an example configuration as
`/etc/porthole/portholed.yaml` (a conffile: your edits survive upgrades), a `porthole` system user and `/var/lib/porthole`.
It does **not** start or enable the service, because the configuration has to be edited first (see
[Quickstart](#1-server)). Upgrading restarts a running server. Removing the package (`apt remove`, `dnf remove`)
keeps the configuration, the data directory and the user; `apt purge` also deletes `/var/lib/porthole` (the token
database) and the user, but leaves anything you added under `/etc/porthole/` (such as certificates).

The client package installs `/usr/bin/porthole`, the systemd unit `porthole.service` of the client daemon, an example
`/etc/porthole/tunnels.yaml` (kept on upgrade) and the `porthole-client` system user and group. It does not enable or
start the service either; see [Run the client as a service](#run-the-client-as-a-service). Both packages can be
installed on one machine: they share only the directory `/etc/porthole`. `apt purge porthole` also deletes
`/etc/porthole/config.yaml` and `/etc/porthole/token` (the stored credentials) and the user and group.

The packages themselves are not signed (apt and dnf will say so); check them against the signed `checksums.txt` as
described in [Verifying a download](#verifying-a-download). There is no apt or dnf repository yet.

### Docker

Images are published to GitHub Container Registry for linux/amd64 and linux/arm64, based on distroless and running as
a non-root user: `ghcr.io/eto-a/porthole/portholed` (server) and `ghcr.io/eto-a/porthole/porthole` (client). Tags are
the version without the leading `v` (for example `0.1.0`); `latest` follows the newest stable release and is not set
for pre-releases.

```console
$ docker run --rm ghcr.io/eto-a/porthole/portholed:<version> version
$ docker run -d --name portholed --restart unless-stopped \
    -p 443:443 -p 20000-20099:20000-20099 \
    -e PORTHOLED_DOMAIN=tun.example.com -e PORTHOLED_TCP_PORT_RANGE=20000-20099 \
    -e PORTHOLED_TLS_CERT_FILE=/etc/porthole/tls/fullchain.pem -e PORTHOLED_TLS_KEY_FILE=/etc/porthole/tls/privkey.pem \
    -v /etc/letsencrypt/live/tun.example.com:/etc/porthole/tls:ro \
    -v porthole-data:/var/lib/porthole \
    ghcr.io/eto-a/porthole/portholed:<version> serve --config ""
$ docker exec portholed portholed token create --name home --config ""
```

The certificate files must be readable by uid 65532 (and `live/` holds symlinks into `archive/`, so mount the
`/etc/letsencrypt` tree or copy the files). Instead of environment variables you can mount a configuration file at
`/etc/porthole/portholed.yaml` and drop `--config ""`; see also [deploy/compose.yaml](deploy/compose.yaml), which builds
the image from source.

The client image is meant for sidecar use; it reads `PORTHOLE_SERVER` and `PORTHOLE_TOKEN` from the environment and
reaches targets by host name on the container network:

```console
$ docker run --rm -e PORTHOLE_SERVER=https://tun.example.com -e PORTHOLE_TOKEN=ph_... \
    ghcr.io/eto-a/porthole/porthole:<version> http web:8080
```

### Archives

Download an archive for your platform from [Releases](https://github.com/eto-a/porthole/releases): `portholed_*` for
the server, `porthole_*` for clients (Linux, macOS and Windows; amd64 and arm64). Each archive contains a single static
binary; extract it and put it on your `PATH`. Each archive also has an SPDX SBOM (`*.sbom.json`) next to it.

### Verifying a download

Every release is signed and carries build provenance. `checksums.txt` lists the SHA-256 of every archive and package
and is signed with cosign (keyless, by the release workflow). To check what you downloaded:

```console
$ sha256sum --check --ignore-missing checksums.txt
$ cosign verify-blob --bundle checksums.txt.sigstore.json \
    --certificate-identity-regexp '^https://github.com/eto-a/porthole/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
$ gh attestation verify porthole_<version>_linux_amd64.tar.gz --repo eto-a/porthole
```

`gh attestation verify` works the same for the `.deb` and `.rpm` files. Container images are signed with cosign too, and
their digests carry a build provenance attestation:

```console
$ cosign verify ghcr.io/eto-a/porthole/portholed:<version> \
    --certificate-identity-regexp '^https://github.com/eto-a/porthole/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
$ gh attestation verify oci://ghcr.io/eto-a/porthole/portholed:<version> --repo eto-a/porthole
```

## Quickstart

### 1. Server

You need a machine with a public IP address and a domain you control. The examples use `tun.example.com`. Install
`portholed` first, see [Installation](#installation); the deb and rpm packages also set up the systemd unit and the
`porthole` user.

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

Certificates are read from files and a renewed one is picked up without a restart: within a minute, or immediately
after `systemctl reload portholed` (SIGHUP), which is what your renewal hook should run. Alternatively, run `portholed`
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

**Run it.** With the deb or rpm package the unit and the `porthole` user already exist and the example configuration
is installed as `/etc/porthole/portholed.yaml`: edit it as above, then

```console
$ sudo systemctl enable --now portholed
$ sudo systemctl status portholed
```

Without a package, run it by hand (or install the unit [deploy/portholed.service](deploy/portholed.service) yourself, see
the comments in it) or use a container image (see [Installation](#docker)):

```console
$ portholed serve --config /etc/porthole/portholed.yaml
```

**Create a token** (one per client machine; the name becomes the client name in the public URLs):

```console
$ sudo -u porthole portholed token create --name home
```

The token is shown once (the server stores only a hash), together with a ready-to-use `porthole login` command. The
`token` commands read the same configuration and database as `serve` (use `--config` if it is not at
`/etc/porthole/portholed.yaml`). Run them as the user the service runs as (`sudo -u porthole` above): a database created
by root cannot be opened by the service. Under Docker, use `docker exec` as shown in [Installation](#docker). Token names
are 1-32 characters of `a-z`, `0-9` and `-`. More options (without the `sudo -u porthole` prefix):

```console
$ portholed token create --name office-nas --expires 30d --scopes tunnel:http,tunnel:tcp --max-tunnels 5
$ portholed token list            # --all includes revoked tokens, --json prints a JSON array
$ portholed token revoke home     # by id or name; takes effect on live sessions
```

### 2. Client

Install `porthole` first: `curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh`, see
[Installation](#installation) for other ways.

```console
$ porthole login https://tun.example.com ph_...      # stores the server and token in your user config
$ porthole login https://tun.example.com ph_... --check   # also connects to the server and verifies the token

$ porthole http 8080                  # https://http-8080-home.tun.example.com
$ porthole http 8080 --name blog      # https://blog-home.tun.example.com
$ porthole tcp 7575                   # tcp://tun.example.com:<port from the range>
$ porthole tcp 192.168.1.5:7575 --remote-port 20017
$ porthole ssh                        # TCP tunnel to localhost:22 (or an SSH-gateway tunnel, see below)
```

**SSH through the gateway.** When the server enables `ssh_gateway.listen` (for example `:2222`), `porthole ssh` is
reachable by the client name through the gateway, with no public TCP port:

```console
$ ssh -J tun.example.com:2222 user@home          # "home" is the client name; "nas-home" is tunnel nas of client home
```

or once in `~/.ssh/config`:

```
Host home
    HostName home
    User user
    ProxyJump tun.example.com:2222
```

The gateway only forwards `direct-tcpip` channels, so it never gives a shell on the server; compare its host key
fingerprint (in the server log, or `portholed ssh-hostkey`) on the first connection. With `porthole ssh --private`
the gateway first asks for a porthole token of the same client (or one with the scope `connect:<client>`) as the
password of the jump host, which you select with the user name `token`: `ssh -J token@tun.example.com:2222 user@home`
(`ProxyJump token@tun.example.com:2222`). Afterwards you enter the target's own password or use your key as usual.

Commands run in the foreground, print the public address, and reconnect automatically if the connection drops.
If the server cannot be reached at all when the command starts (wrong URL, server down), it gives up after 5
attempts, or at once on an unknown host name or an untrusted certificate; change the limit with
`--max-initial-attempts N` (`0` retries forever). Once connected, the command keeps reconnecting. To keep tunnels up
across reboots, run the client as a service instead: see
[Run the client as a service](#run-the-client-as-a-service).

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
| `porthole http\|tcp\|ssh ... [--detach\|--no-daemon\|--daemon]` | With a running daemon, add the tunnel to it (`--detach`: keep it after the command exits); `--no-daemon` runs it in this process, `--daemon` requires the daemon |
| `porthole daemon [--config] [--tunnels] [--socket]` | Run the client daemon: the tunnels file plus tunnels added from the CLI |
| `porthole start [names...]` | Run the tunnels of the tunnels file in the foreground, without a daemon |
| `porthole status` | Show the daemon's connection and tunnels |
| `porthole reload` | Make the daemon re-read the tunnels file |
| `porthole close <name>` | Close a tunnel added with `--detach` |
| `porthole version` | Print the version |

## Run the client as a service

`porthole daemon` keeps one session to the server and the tunnels listed in a tunnels file up across reboots and
network drops, and accepts more tunnels from the CLI over a local unix socket. Design: [ADR 0002](docs/adr/0002-client-daemon-and-tunnels-file.md).

### Linux, system-wide (deb and rpm)

```console
$ sudo apt install ./porthole_<version>_linux_amd64.deb     # or: sudo dnf install ./porthole_<version>_linux_amd64.rpm
$ sudo porthole login --config /etc/porthole/config.yaml https://tun.example.com ph_...
$ sudo chown porthole-client: /etc/porthole/config.yaml && sudo chmod 0600 /etc/porthole/config.yaml
$ sudoedit /etc/porthole/tunnels.yaml
$ sudo systemctl enable --now porthole
$ sudo usermod -aG porthole-client "$USER"      # log in again afterwards
$ porthole status
```

The daemon runs as the `porthole-client` user (created by the package; it is not the server's `porthole` user), so that
user must be able to read the credentials: the commands above hand `config.yaml` to that user, readable by nobody
else. Instead of keeping the token in `config.yaml` you can put it in a file of its own, for example
`/etc/porthole/token` (one line, owned by `porthole-client`, mode `0600`; porthole refuses a token file that its group
or others can read, like ssh does for private keys), and set `token_file: /etc/porthole/token` in
`config.yaml` instead of `token`.

The tunnels file holds no secrets (see [deploy/tunnels.example.yaml](deploy/tunnels.example.yaml), also installed as
`/usr/share/doc/porthole/tunnels.example.yaml`; the entries of the shipped file are all disabled):

```yaml
version: 1
tunnels:
  blog:
    type: http
    addr: 3000
  db:
    type: tcp
    addr: nas.local:5432
    remote_port: 20017    # optional
  ssh:
    type: ssh             # TCP tunnel to 127.0.0.1:22 unless addr is given
```

After editing it run `sudo systemctl reload porthole` or `porthole reload`: the file is validated first, a broken file
is rejected and the running tunnels stay as they are. A broken file at start stops the service for good (exit code 78)
instead of restarting it in a loop; look at `journalctl -u porthole`.

Members of the group `porthole-client` (and root) can use the daemon's socket, `/run/porthole/porthole.sock`. Adding a
tunnel publishes a local service to the Internet, so treat the group like the `docker` group. With the daemon running:

```console
$ porthole http 3000                  # attaches to the daemon; the tunnel closes when you press Ctrl-C
$ porthole http 3000 --detach         # stays until `porthole close http-3000` or a daemon restart
$ porthole close <name>
$ porthole status
```

Tunnels added from the command line are not written to the file: what runs after a reboot is exactly the tunnels file.
If a daemon is running but you may not use its socket, `porthole http` fails with a hint instead of starting a second
session with the same token (that would replace the daemon's session). `--no-daemon` forces a standalone run, and
`--daemon` makes the command fail when no daemon is reachable.

### Linux, as your own user

No root and no extra user: copy [deploy/porthole.user.service](deploy/porthole.user.service) to
`~/.config/systemd/user/porthole.service`, run `porthole login` and create `~/.config/porthole/tunnels.yaml`, then
`systemctl --user enable --now porthole` (the header of the unit has the details, including `loginctl enable-linger`).
The socket is then `$XDG_RUNTIME_DIR/porthole/porthole.sock`, which only you can reach.

### macOS and Windows

There are no service definitions yet. Run `porthole daemon` yourself, for example in a terminal or from your login
items or Task Scheduler. It uses the per-user configuration directory (`porthole login` writes the credentials there)
and a per-user socket, so `porthole http 3000` finds it by itself.

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
