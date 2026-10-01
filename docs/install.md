# Installation

You do not need to build anything. porthole has two programs, installed in two places:

- **Server** (`portholed`): once, on a machine with a public IP address and a domain, usually a small VPS.
- **Client** (`porthole`): on every machine whose services you want to expose, or that your agent should manage. A client needs only an outbound connection to the server.

Both come from the [GitHub releases](https://github.com/eto-a/porthole/releases): an install script, a Linux package, a container image or an archive (Linux and macOS on amd64 and arm64; Windows has archives only). To build from source instead, see [Building from source](#building-from-source).

> Packages and container images are produced by the release workflow, so they exist for releases made after v0.1.0-alpha.1. That release has archives only; the install script falls back to them.

## With your agent

The quickest way: paste this into Claude Code, or any coding agent that can run shell commands, on the machine you work from:

```text
Set up porthole for me: follow https://raw.githubusercontent.com/eto-a/porthole/main/docs/agent-install.md — ask me only what you can't find out yourself.
```

The agent asks for what it cannot detect (server or client, the VPS and SSH access to it, the domain, which ports to open, whether to connect MCP), then runs the steps below for you and checks the result. The full instructions it follows are in [Install with an agent](agent-install.md); read them if you want to know what it will do.

To install by hand, follow the sections below. After installing, continue with [Server setup](server.md) (`portholed`) or the [Client guide](client.md) (`porthole`). For a first run from scratch, see the [quickstart](quickstart.md).

## Server (once, on a VPS)

Point the domain and a wildcard at the server ([DNS](server.md#dns)) and open the ports listed under [Firewall](server.md#firewall). By default the server gets its HTTPS certificates itself ([TLS](server.md#tls)).

### Install script (Linux and macOS)

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server    # server: portholed
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh                   # client: porthole
```

The script detects your OS and CPU, downloads the release, checks its SHA-256 against `checksums.txt` and installs it, using `sudo` only when needed. If [cosign](https://docs.sigstore.dev) is installed it also verifies the signature of `checksums.txt`. Nothing is installed when a check fails. To read it first, download it and run it: `curl -fsSL -o install.sh https://raw.githubusercontent.com/eto-a/porthole/main/install.sh`, then `sh install.sh --help`.

| Option | Meaning |
|---|---|
| `--client` | Install the client, `porthole` (the default). Cannot be combined with `--server`: run the script once for each |
| `--server` | Install `portholed` instead of `porthole`. On Debian/Ubuntu and RHEL/Fedora (as root or with sudo) this installs the `.deb`/`.rpm`, including the systemd unit and the `porthole` user; elsewhere only the binary |
| `--version v0.1.0` | Install this release. Default: the latest stable release; while there is no stable release yet, the newest pre-release (the script says so) |
| `--prerelease` | Take the newest release including pre-releases, even if a stable one exists |
| `--bin-dir DIR` | Where to put the binary. Default `/usr/local/bin`, or `~/.local/bin` if that is not writable |
| `--archive` | With `--server`, install the binary from the archive even where a package could be used |
| `--no-verify-signature` | Skip the cosign check even if cosign is installed (SHA-256 is always checked) |
| `--dry-run` | Print what would be done and exit |

Without `--version` the script asks the GitHub API for the latest release (60 requests per hour per IP address); with `--version` it makes no API call. Without cosign, the SHA-256 check only protects against a corrupted download, not against a tampered release: see [Verifying a download](#verifying-a-download). The version, given or returned by the API, must look like `v1.2.3` or `v1.2.3-rc.1`; anything else is refused. Downloads use HTTPS only and TLS 1.2 or newer (curl, and GNU wget; BusyBox wget cannot enforce this, so install curl there). Piping a script from the network to `sh` trusts the network and `main`: to review it first, download it, read it and pin a release (`--version vX.Y.Z`).

### Packages (Debian, Ubuntu, Fedora, RHEL and derivatives)

Download the package for your CPU from [Releases](https://github.com/eto-a/porthole/releases) (`portholed_*` is the server; amd64 and arm64) and install it:

```console
$ sudo apt install ./portholed_<version>_linux_amd64.deb        # Debian, Ubuntu
$ sudo dnf install ./portholed_<version>_linux_amd64.rpm        # Fedora, RHEL, Rocky, Alma
```

The server package installs the binary in `/usr/bin`, the systemd unit `portholed.service`, an example configuration as `/etc/porthole/portholed.yaml` (a conffile: your edits survive upgrades), a `porthole` system user and `/var/lib/porthole`. It does **not** start or enable the service, because the configuration has to be edited first (see [Server setup](server.md)). Upgrading restarts a running server. Removing the package (`apt remove`, `dnf remove`) keeps the configuration, the data directory and the user; `apt purge` also deletes `/var/lib/porthole` (the token database) and the user, but leaves anything you added under `/etc/porthole/` (such as certificates).

The client package installs `/usr/bin/porthole`, the systemd unit `porthole.service` of the client daemon, an example `/etc/porthole/tunnels.yaml` (created only if missing, so your edits always survive upgrades; a pristine copy stays in `/usr/share/porthole/tunnels.example.yaml`) and the `porthole-client` system user and group. It does not enable or start the service either; see [Run the client as a service](client.md#run-the-client-as-a-service). Both packages can be installed on one machine: they share only the directory `/etc/porthole`. `apt purge porthole` also deletes `/etc/porthole/config.yaml`, `/etc/porthole/token` (the stored credentials) and `/etc/porthole/tunnels.yaml`, and the user and group.

Non-interactive upgrade from 0.3.0-alpha.2 or older: those versions shipped `tunnels.yaml` as a conffile, so if you edited it and the example changed in the new package, dpkg asks what to do and fails without a terminal (`end of file on stdin at conffile prompt`). Keep your file with `sudo apt-get install -o Dpkg::Options::=--force-confold ./porthole_<version>_linux_amd64.deb`. This applies only to the upgrade from such a version; later versions never ask. rpm keeps an edited file as `tunnels.yaml.rpmsave` and the new package restores it.

The packages themselves are not signed (apt and dnf will say so); check them against the signed `checksums.txt` as described in [Verifying a download](#verifying-a-download). There is no apt or dnf repository yet.

### Docker

Images are published to GitHub Container Registry for linux/amd64 and linux/arm64, based on distroless and running as a non-root user: `ghcr.io/eto-a/porthole/portholed` (server) and `ghcr.io/eto-a/porthole/porthole` (client). Tags are the version without the leading `v` (for example `0.1.0`); `latest` follows the newest stable release and is not set for pre-releases.

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

The certificate files must be readable by uid 65532 (and `live/` holds symlinks into `archive/`, so mount the `/etc/letsencrypt` tree or copy the files). Instead of environment variables you can mount a configuration file at `/etc/porthole/portholed.yaml` and drop `--config ""`; see also [deploy/compose.yaml](../deploy/compose.yaml), which builds the image from source (more in [Docker Compose](server.md#docker-compose)). The client image is described under [Docker (sidecar)](#docker-sidecar) in the client section.

### Dokploy

On a server that runs [Dokploy](https://dokploy.com), whose Traefik owns ports 80 and 443, deploy the ready compose file [deploy/dokploy-compose.yaml](../deploy/dokploy-compose.yaml): create a Compose service, choose Raw, paste it and set `PORTHOLED_DOMAIN` and your domain in the labels. Traefik passes TLS through to `portholed`, which keeps getting the certificates itself. Details and the PROXY protocol setup: [Behind Traefik or Dokploy](server.md#behind-traefik-or-dokploy-tls-passthrough); step by step: [deploy.md](deploy.md).

### Server archive

Take the `portholed_*` archive and unpack it as described under [Archives](#archives).

## Clients (on every machine)

Install `porthole`, then enrol the machine with a one-time link from the server: `porthole join <link>` (see [Join with a link](client.md#join-with-a-link)).

### Install script for the client

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
```

This is the same script and the same options as for the server (see the [table above](#install-script-linux-and-macos)), without `--server`. It works on Linux and macOS; on Windows use an archive.

### Client packages (Debian, Ubuntu, Fedora, RHEL and derivatives)

```console
$ sudo apt install ./porthole_<version>_linux_amd64.deb         # client
$ sudo dnf install ./porthole_<version>_linux_amd64.rpm
```

The client package installs `/usr/bin/porthole`, the systemd unit `porthole.service` of the client daemon, an example `/etc/porthole/tunnels.yaml` (kept on upgrade) and the `porthole-client` system user and group. It does not enable or start the service either; see [Run the client as a service](client.md#run-the-client-as-a-service). Both packages can be installed on one machine: they share only the directory `/etc/porthole`. `apt purge porthole` also deletes `/etc/porthole/config.yaml` and `/etc/porthole/token` (the stored credentials) and the user and group. The packages are not signed; see [Verifying a download](#verifying-a-download).

### Docker (sidecar)

The client image is meant for sidecar use; it reads `PORTHOLE_SERVER` and `PORTHOLE_TOKEN` from the environment and reaches targets by host name on the container network:

```console
$ docker run --rm -e PORTHOLE_SERVER=https://tun.example.com -e PORTHOLE_TOKEN=ph_... \
    ghcr.io/eto-a/porthole/porthole:<version> http web:8080
```

### Archives

Download an archive for your platform from [Releases](https://github.com/eto-a/porthole/releases): `portholed_*` for the server, `porthole_*` for clients (Linux, macOS and Windows; amd64 and arm64). Each archive contains a single static binary; extract it and put it on your `PATH`. Each archive also has an SPDX SBOM (`*.sbom.json`) next to it. On Windows and on macOS without the script this is the way to install the client; see the two sections below.

### Windows

Packages for Scoop and winget are coming (the release generates their manifests, but they are not published yet). Until then:

1. Download `porthole_<version>_windows_amd64.zip` (or `_arm64`) from [Releases](https://github.com/eto-a/porthole/releases) and extract `porthole.exe` to a directory of your choice, for example `C:\Program Files\porthole`. Add it to `PATH`. Browsers may show SmartScreen for an unsigned exe; see [Troubleshooting](troubleshooting.md#windows-smartscreen-and-macos-gatekeeper).
2. Enrol the machine: `porthole join <link>`.
3. To keep tunnels up across reboots, run `porthole service install` in an **Administrator** terminal (available from v0.4). It registers the Windows service `porthole`; see [Run the client as a service](client.md#porthole-service-linux-macos-windows). If you do not want a system service, run `porthole daemon` from Task Scheduler instead (recipe in the same section).

### macOS

Homebrew (`brew install eto-a/tap/porthole`) is coming; the tap is not published yet. Until then use the install script above or the tarball:

```console
$ tar -xzf porthole_<version>_darwin_arm64.tar.gz porthole        # or _darwin_amd64 on an Intel Mac
$ sudo install -m 0755 porthole /usr/local/bin/porthole
```

The binary is not notarized yet, so Gatekeeper blocks a file downloaded in a browser ("cannot be opened because the developer cannot be verified"). Remove the quarantine attribute once you have checked the download ([Verifying a download](#verifying-a-download)):

```console
$ xattr -d com.apple.quarantine /usr/local/bin/porthole
```

`curl` and the install script do not set the attribute, so they are not affected. To keep tunnels up across reboots (available from v0.4): `porthole service install --user` registers a LaunchAgent that runs while you are logged in; `sudo porthole service install` registers a system LaunchDaemon. See [Run the client as a service](client.md#porthole-service-linux-macos-windows).

## Verifying a download

Every release is signed and carries build provenance. `checksums.txt` lists the SHA-256 of every archive and package and is signed with cosign (keyless, by the release workflow). To check what you downloaded:

```console
$ sha256sum --check --ignore-missing checksums.txt
$ cosign verify-blob --bundle checksums.txt.sigstore.json \
    --certificate-identity-regexp '^https://github.com/eto-a/porthole/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
$ gh attestation verify porthole_<version>_linux_amd64.tar.gz --repo eto-a/porthole
```

`gh attestation verify` works the same for the `.deb` and `.rpm` files. Container images are signed with cosign too, and their digests carry a build provenance attestation:

```console
$ cosign verify ghcr.io/eto-a/porthole/portholed:<version> \
    --certificate-identity-regexp '^https://github.com/eto-a/porthole/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
$ gh attestation verify oci://ghcr.io/eto-a/porthole/portholed:<version> --repo eto-a/porthole
```

## Building from source

Requires Go 1.27 or newer.

```console
$ go build ./cmd/...          # binaries in the current directory
$ make build                  # static, stripped, versioned binaries in ./bin
$ make lint test              # needs golangci-lint v2
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the development workflow.
