# Install porthole with an agent

These are instructions for an LLM coding agent (Claude Code or any agent that can run shell commands). A person pasted a short prompt that points here; your job is to set up porthole for them, end to end, and to ask them only what you cannot find out yourself.

If you are a person reading this: you do not need to follow it by hand. Paste this into your agent instead:

```text
Set up porthole for me: follow https://raw.githubusercontent.com/eto-a/porthole/main/docs/agent-install.md — ask me only what you can't find out yourself.
```

The manual path is in [Installation](install.md) and the [Quick start](quickstart.md).

## What porthole is

porthole is a self-hosted alternative to ngrok with two programs:

- `portholed`, the **server**: one per setup, on a machine with a public IP address and a domain (usually a small VPS).
- `porthole`, the **client**: on every machine whose services should be reachable, usually behind NAT. It needs only an outbound connection to the server on port 443.

A client is enrolled with a one-time **join link** created on the server. Every HTTP tunnel gets a subdomain such as `https://http-3000-home.tun.example.com` with a certificate the server obtains from Let's Encrypt by itself. Both programs have MCP servers, so you can manage porthole after the install.

Reference documents, as raw Markdown you can fetch: [server](https://raw.githubusercontent.com/eto-a/porthole/main/docs/server.md), [client](https://raw.githubusercontent.com/eto-a/porthole/main/docs/client.md), [agents (MCP)](https://raw.githubusercontent.com/eto-a/porthole/main/docs/agents.md), [deploy](https://raw.githubusercontent.com/eto-a/porthole/main/docs/deploy.md), [troubleshooting](https://raw.githubusercontent.com/eto-a/porthole/main/docs/troubleshooting.md). If a command below fails in a way they do not explain, run it with `--help`: the binaries are the source of truth.

## Goals

At the end, report to the person:

1. The server runs and answers `ok` at `https://<domain>/healthz` (if a server was part of the task).
2. Each client is enrolled, and a test tunnel was reachable from the internet.
3. Tunnels that should stay up are listed in `tunnels.yaml` and the client runs as a service (if they asked for that).
4. MCP is connected in Claude Code (if they asked for that).
5. What you changed on each machine: packages, files, firewall rules, services.

## Safety rules

- **Secrets.** Do not print tokens (`ph_...`) or join links in your replies, and do not write them into files other than the ones porthole reads. Prefer join links to tokens: a link works once and expires after 15 minutes. When a command prints a token, capture it into a variable or file instead of echoing it.
- **Ask before** opening firewall ports, changing DNS, installing packages on a machine the person did not name, or replacing an existing porthole configuration (`porthole join` refuses to replace another server's credentials without `--force`; do not add `--force` on your own).
- **Remote control.** Do not add `allow_remote: any` or LAN targets to a client's `tunnels.yaml` unless the person asks for exactly that. Without the key, the server can only ask a machine to expose its own loopback ports and `ssh`.
- **Scopes.** Give MCP tokens only the scopes the person needs; `admin:read` for looking around. Do not grant `admin:tokens` or `admin:remote` unless asked.
- **Exposure.** Every tunnel makes a local service reachable from the internet. Open only what the person asked for.

## Step 1. Ask what you cannot detect

Ask these in one message, and skip any you can already answer from the conversation or the machine:

1. **Role of this setup:** a new server, a client for an existing server, or both?
2. **Server:** the VPS address and how you reach it (`ssh user@host`, and whether that user has `sudo`). For a client of an existing server: a join link from its operator, or SSH access to the server so you can create one.
3. **Domain:** the base domain for tunnels (for example `tun.example.com`), and whether the person can create DNS records for it (or whether you have a tool for their DNS provider).
4. **Extras:** SSH by name (needs port `2222` open on the server), TCP tunnels (needs a port range open), and which local services should be published (ports).
5. **MCP:** connect porthole to Claude Code after the install? For the server (operator tools), for this machine (open and close its tunnels), or both?

## Step 2. Detect

Run these yourself on every machine you will touch (over SSH for the server) and do not ask about anything they answer:

```console
$ uname -sm                                     # OS and CPU: Linux/Darwin, x86_64/aarch64/arm64
$ cat /etc/os-release                           # Debian/Ubuntu or Fedora/RHEL get a package with a systemd unit
$ id -u; sudo -n true && echo "sudo ok"         # root or passwordless sudo?
$ command -v systemctl                          # systemd present?
$ command -v portholed porthole                 # already installed?
$ portholed version; porthole version           # which version
$ ls /etc/porthole/ 2>/dev/null                 # existing configuration
$ sudo ss -ltnp | grep -E ':(80|443|2222)\b'    # is something else on these ports? (on the server)
$ command -v docker                             # Docker present? Is Dokploy or another proxy on 80/443?
```

Check DNS from any machine (the server's public IP should come back for both names; `anything` stands for any tunnel name):

```console
$ dig +short tun.example.com A
$ dig +short anything.tun.example.com A
$ curl -fsS https://api.ipify.org               # on the server: its public IPv4 address, to compare
```

Decide from the results:

- Ports 80 and 443 free on the server: use the **package or binary** path below (systemd), or Docker Compose if the person prefers containers.
- Traefik of **Dokploy** on 80 and 443: use the Dokploy path in [deploy.md](https://raw.githubusercontent.com/eto-a/porthole/main/docs/deploy.md) (TLS passthrough; `portholed` still gets its own certificates).
- Another reverse proxy (Caddy, nginx) already serves sites there: follow "Behind a reverse proxy" in [server.md](https://raw.githubusercontent.com/eto-a/porthole/main/docs/server.md). Tell the person this path needs a wildcard certificate on the proxy.
- DNS records missing or wrong: tell the person exactly which two records to create, `tun.example.com A <ip>` and `*.tun.example.com A <ip>`, and wait until `dig` shows them before you start the server (certificates are requested on the first visit of each name and Let's Encrypt limits failed attempts).

## Step 3. Install the server

Skip this step for a client of an existing server.

With systemd, on Debian, Ubuntu, Fedora, RHEL and derivatives (installs the `.deb` or `.rpm`: binary, systemd unit, `porthole` user, example configuration `/etc/porthole/portholed.yaml`); elsewhere it installs only the binary:

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server
```

The script checks the SHA-256 of the download (and the cosign signature if cosign is installed); `sh install.sh --help` lists its options, for example `--version vX.Y.Z` to pin a release. Only pre-releases exist so far, and the script says when it takes one.

Set the domain. The only required change in the example configuration is the `domain` line; the default TLS mode, `acme`, gets a certificate per host name from Let's Encrypt with no DNS provider and no renewal job:

```console
$ sudo sed -i 's/^domain: .*/domain: tun.example.com/' /etc/porthole/portholed.yaml
```

For SSH by name, also enable the gateway in the same file (the example has it commented out):

```yaml
ssh_gateway:
  listen: ":2222"
```

Optionally set `tls.acme.email` for expiry notices. Unknown keys are rejected, so keep the indentation of the example.

Open the firewall, after asking the person: TCP `443` and `80` (certificates and the redirect), `2222` if the SSH gateway is on, and the TCP tunnel range (`tcp_port_range`, default `20000-29999`) if they want TCP tunnels. With ufw, for example `sudo ufw allow 80,443/tcp`. Cloud providers often have a separate firewall in their web console; tell the person if the ports look closed from outside although the host firewall is open.

Start it:

```console
$ sudo systemctl enable --now portholed
$ sudo systemctl status portholed --no-pager
$ curl -fsS https://tun.example.com/healthz
ok
```

If the service does not start, read `journalctl -u portholed -n 50 --no-pager` (the log is JSON). Without a package, see "Run it" in [server.md](https://raw.githubusercontent.com/eto-a/porthole/main/docs/server.md) for the unit file; with Docker, see [deploy.md](https://raw.githubusercontent.com/eto-a/porthole/main/docs/deploy.md).

### Create a join link

One link per machine; the name becomes part of its addresses (`https://<tunnel>-<name>.tun.example.com`) and its SSH name. Commands that talk to the running server must run as the service user:

```console
$ sudo -u porthole portholed join create --name home
Join link for "home" (id 3kq9w2m1z8xa), valid until 2026-10-01 12:15 UTC and usable once.

On the machine, run:

    porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...
```

In Docker the same command runs inside the container: `docker exec <container> /usr/local/bin/portholed join create --name home --config ""`. Useful options: `--ttl 2h` (default 15 minutes), `--expires 30d` (lifetime of the token the link creates), `--no-remote-control` (the server may not ask this machine to open tunnels).

If you install the client yourself, pass the link straight to the client machine; do not show it in your reply. If the person installs the client, give them the `porthole join` command.

## Step 4. Install a client

On Linux and macOS:

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
$ porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...
joined as home
```

The script installs the binary into `/usr/local/bin`, or `~/.local/bin` if that is not writable. On Windows, download the `porthole_<version>_windows_amd64.zip` (or `arm64`) archive from the [releases](https://github.com/eto-a/porthole/releases), extract `porthole.exe` and put it on the `PATH`.

Test a tunnel. Ask which local port to use, or start a throwaway server (`python3 -m http.server 3000`):

```console
$ porthole http 3000
connected as home
https://http-3000-home.tun.example.com -> 127.0.0.1:3000
```

The command stays in the foreground; run it in the background or a second shell, then check from the client machine or the server:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' https://http-3000-home.tun.example.com
```

The first request to a new name waits a few seconds while the server gets its certificate. Stop the test tunnel afterwards unless the person wants it.

### Tunnels that stay up (Linux service)

The service needs the client package, which install.sh does not install for the client. Download the package of the same release for the CPU (`amd64` or `arm64`) from the [releases](https://github.com/eto-a/porthole/releases); package names carry the version without the leading `v`:

```console
$ V=0.3.0-alpha.2        # the release install.sh reported; `porthole version` shows it too
$ curl -fsSLO "https://github.com/eto-a/porthole/releases/download/v$V/porthole_${V}_linux_amd64.deb"
$ sudo apt install "./porthole_${V}_linux_amd64.deb"         # Fedora/RHEL: the .rpm and sudo dnf install
```

Packages are not signed themselves; `checksums.txt` of the release lists their SHA-256 (see "Verifying a download" in [install.md](https://raw.githubusercontent.com/eto-a/porthole/main/docs/install.md)).

The package installs `/usr/bin/porthole`, the unit `porthole.service`, the user `porthole-client` and `/etc/porthole/tunnels.yaml` with every entry disabled. Enrol the machine into the system-wide configuration, which the service reads:

```console
$ sudo porthole join --config /etc/porthole/config.yaml https://tun.example.com/j/pj_...
$ sudo chown porthole-client: /etc/porthole/config.yaml && sudo chmod 0600 /etc/porthole/config.yaml
```

Write the tunnels the person asked for into `/etc/porthole/tunnels.yaml`:

```yaml
version: 1
tunnels:
  blog: {type: http, addr: 3000}
  ssh:  {type: ssh}
```

Then start the service and check it:

```console
$ sudo systemctl enable --now porthole
$ sudo porthole status
```

`porthole status` talks to the running daemon and fails (exit status 6) when none is running or the user may not use its socket; members of the `porthole-client` group can run it without `sudo` (`sudo usermod -aG porthole-client "$USER"`, then log in again). After later edits of `tunnels.yaml` run `sudo systemctl reload porthole`. For a per-user service without root, macOS and Windows, see "Run the client as a service" in [client.md](https://raw.githubusercontent.com/eto-a/porthole/main/docs/client.md).

### SSH by name

If the server has the SSH gateway on and the machine has a `ssh` tunnel (`porthole ssh`, or `ssh: {type: ssh}` in `tunnels.yaml`), anyone with an account on the machine connects with stock OpenSSH:

```console
$ ssh -J tun.example.com:2222 alice@home
```

`portholed ssh-hostkey` on the server prints the gateway's host key fingerprint; give it to the person so they can compare it on the first connection.

## Step 5. Connect MCP (Claude Code)

Only if the person asked. Commands are from [agents.md](https://raw.githubusercontent.com/eto-a/porthole/main/docs/agents.md).

**This machine** (open, close and list its tunnels; needs the client daemon from the previous step, no token):

```console
$ claude mcp add porthole-local -- porthole mcp
```

**The server, over SSH** (no token: access to the server's admin socket is the permission). Preferred when the person's machine can SSH to the server as root or as the `porthole` user. Add `--read-only` unless they want the agent to change things:

```console
$ claude mcp add porthole -- ssh root@tun.example.com portholed mcp --read-only
```

**The server, over HTTPS** (needs a token with admin scopes). Create the token on the server and pass it to Claude Code without printing it, for example with `jq` on the machine you run on:

```console
$ TOKEN=$(ssh user@tun.example.com sudo -u porthole portholed token create --name ops-agent --scopes admin:read --json | jq -r .token)
$ claude mcp add --transport http porthole https://tun.example.com/_porthole/mcp --header "Authorization: Bearer $TOKEN"
$ unset TOKEN
```

Add scopes only on request: `admin:tunnels` (close tunnels), `admin:remote` (ask a client to open a tunnel), `admin:tokens` (join links, revoke tokens), `admin:traffic` (headers and bodies of inspected requests). Consider `--expires 30d`.

Tell the person to restart Claude Code (or run `/mcp`) so the new server is loaded, then check with a read-only call such as `server_status` or `status`.

## Step 6. Verify and report

- Server: `systemctl is-active portholed` prints `active`; `curl -fsS https://tun.example.com/healthz` prints `ok`.
- Client: `porthole join` printed `joined as <name>`; a test tunnel answered over HTTPS; with the service, `porthole status` lists the tunnels of `tunnels.yaml`.
- SSH by name (if enabled): `ssh -J tun.example.com:2222 <user>@<name> true` succeeds.
- MCP (if added): `claude mcp list` shows the servers.

Then give the person the summary from [Goals](#goals).

## When something fails

Look up the error in [troubleshooting.md](https://raw.githubusercontent.com/eto-a/porthole/main/docs/troubleshooting.md). The usual causes:

- **Certificate not issued, browser warning:** DNS does not point at the server yet, or port 80 or 443 is closed from outside. Fix it before retrying; repeated failures count against Let's Encrypt limits.
- **`porthole join` refused:** the link was already used, expired (`--ttl`, default 15 minutes) or was mangled when copied; create a new one. `name_taken` means a token with that name is active: revoke it first (`portholed token revoke <name>`) when you re-enrol a machine.
- **`cannot connect`:** wrong server address, port 443 closed, or the server is not running (`journalctl -u portholed`).
- **`name_taken` or `session_replaced`:** two processes use the same token or tunnel name; every machine needs its own join link.
- **Permission denied on the daemon socket:** the user is not in the `porthole-client` group yet (log in again after `usermod`).

Do not work around a failure by widening access (`allow_remote: any`, more scopes, `--insecure-http`, `--force`) without the person's explicit agreement.
