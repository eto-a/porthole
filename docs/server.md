# Server setup (`portholed`)

`portholed` is the server: it terminates the client sessions, routes HTTP tunnels by `Host`, listens on the public
ports of TCP tunnels and (optionally) runs the [SSH gateway](ssh.md). You need a machine with a public IP address and a
domain you control. The examples use `tun.example.com`.

Install `portholed` first, see [Installation](install.md); the deb and rpm packages also set up the systemd unit and
the `porthole` user. Then follow the steps below: DNS, TLS, configuration, firewall, run, create a token. Client setup
is in the [Client guide](client.md).

## DNS

Point the domain and a wildcard at the server's IP address:

```
tun.example.com.     A   203.0.113.10
*.tun.example.com.   A   203.0.113.10
```

## TLS

`portholed` has three TLS modes, set with `tls.mode` ([ADR 0004](adr/0004-automatic-https-per-tunnel.md)):

| Mode | When | What it does |
|---|---|---|
| `acme` (default) | no certificate files configured | Obtains and renews a certificate per host name itself, from Let's Encrypt by default. No DNS provider and no external renewal job |
| `files` | `tls.cert_file` and `tls.key_file` set | Serves the certificate you provide, for example a wildcard from certbot |
| `off` | behind a proxy that terminates TLS | Plain HTTP, see [Behind a reverse proxy](#behind-a-reverse-proxy) |

An empty `tls.mode` means `files` when the certificate files are set and `acme` otherwise.

### Automatic certificates (`acme`)

Nothing to configure beyond the DNS records above and reachable ports 443 and 80. The first TLS handshake for a host
name triggers issuance (a few seconds, once per name); the certificate is then renewed in the background 30 days
before it expires. Challenges: TLS-ALPN-01 on the HTTPS listener and HTTP-01 on the plain HTTP listener
(`http_listen`, default `:80`), which also redirects every other request to `https://`. `GET /healthz` is answered on
that listener as well. Certificates and the ACME account are stored in `<data_dir>/certs` (keep the directory across
restarts; it must be writable by the service user).

A certificate is requested only for the control host `tun.example.com` and for `<label>.tun.example.com` where the
label belongs to a live tunnel (or to one whose client disconnected a moment ago). Handshakes for any other name fail
without contacting the CA and are logged as `certificate refused` with the host name, so scanners cannot burn your
rate limits.

```yaml
tls:
  mode: acme              # the default
  acme:
    email: you@example.com                                    # optional: expiry notices from the CA
    ca: https://acme-v02.api.letsencrypt.org/directory        # default; see staging below
# http_listen: ":80"      # default in acme mode; "" disables the listener (then only TLS-ALPN-01 works)
```

Things to know:

- **Let's Encrypt limits.** 50 certificates per registered domain per week, and 5 duplicates of the same name per
  week (see [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/)). Every new tunnel name costs one
  certificate; reusing a name costs nothing, because the certificate is already stored. Choose stable names.
- **Staging.** To test without touching the production limits, set
  `tls.acme.ca: https://acme-staging-v02.api.letsencrypt.org/directory`. Staging certificates are not trusted by
  browsers; switch back and clear `<data_dir>/certs` when you go live.
- **Certificate Transparency.** Every issued name is published in public CT logs. Tunnel host names are therefore not
  secret; protect private services with the [SSH gateway](ssh.md) or authentication in the application.
- **Ports.** The CA connects to port 443 and 80 of the domain from the internet. Behind a proxy that owns those
  ports use TLS passthrough, see [Behind Traefik or Dokploy](#behind-traefik-or-dokploy-tls-passthrough).

### Your own certificate (`files`)

If you already have a wildcard certificate (a wildcard does not cover the apex, so it must list both
`tun.example.com` and `*.tun.example.com`), point to it. With certbot and a DNS-01 plugin, for example Cloudflare:

```console
$ certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
    -d tun.example.com -d '*.tun.example.com'
```

```yaml
tls:
  cert_file: /etc/porthole/tls/fullchain.pem
  key_file: /etc/porthole/tls/privkey.pem
```

Certificates are read from files and a renewed one is picked up without a restart: within a minute, or immediately
after `systemctl reload portholed` (SIGHUP), which is what your renewal hook should run. `http_listen` is off in this
mode; set it (for example `":80"`) to get the `https://` redirect.

## Configuration

The file is `/etc/porthole/portholed.yaml` (override with `--config`); the full annotated example is
[deploy/portholed.example.yaml](../deploy/portholed.example.yaml). A minimal one:

```yaml
version: 1
domain: tun.example.com
listen: ":443"
tcp_port_range: "20000-29999"
data_dir: /var/lib/porthole
```

With no `tls` section the server gets its certificates by ACME (see [TLS](#tls)). Unknown keys are rejected. Every setting except `version` and `shutdown_grace` can also be given as a `PORTHOLED_*`
environment variable (they override the file), for example `PORTHOLED_DOMAIN` or `PORTHOLED_TCP_PORT_RANGE`. Pass
`--config ""` to configure the server only through the environment.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `version` | - | required (`1`) | Configuration schema version |
| `domain` | `PORTHOLED_DOMAIN` | required | Base domain, a bare host name (no scheme or port) |
| `listen` | `PORTHOLED_LISTEN` | `:443` | HTTP(S) listener: control endpoint, health check and HTTP tunnels |
| `tls.mode` | `PORTHOLED_TLS_MODE` | `files` if certificate files are set, else `acme` | `acme`, `files` or `off` (plain HTTP behind a TLS-terminating proxy) |
| `tls.cert_file`, `tls.key_file` | `PORTHOLED_TLS_CERT_FILE`, `PORTHOLED_TLS_KEY_FILE` | unset | PEM certificate and key for mode `files`; set both or neither |
| `tls.acme.email` | `PORTHOLED_ACME_EMAIL` | unset | Optional ACME account contact address (mode `acme`) |
| `tls.acme.ca` | `PORTHOLED_ACME_CA` | Let's Encrypt production | ACME directory URL (mode `acme`); the staging URL is in [TLS](#tls) |
| `http_listen` | `PORTHOLED_HTTP_LISTEN` | `:80` in mode `acme`, off otherwise | Plain HTTP listener for ACME HTTP-01 and the `https://` redirect; empty disables it; not allowed in mode `off` |
| `public_scheme`, `public_port` | `PORTHOLED_PUBLIC_SCHEME`, `PORTHOLED_PUBLIC_PORT` | `https`, no port | Scheme and port in the public HTTP tunnel URLs shown to clients; change only for local development or when the public port differs from the listening port |
| `tcp_port_range` | `PORTHOLED_TCP_PORT_RANGE` | `20000-29999` | Inclusive range of public ports for TCP (and `--public-port` SSH) tunnels |
| `tcp_bind_host` | `PORTHOLED_TCP_BIND_HOST` | all interfaces | Address the TCP tunnel listeners bind to |
| `data_dir` | `PORTHOLED_DATA_DIR` | `/var/lib/porthole` | Directory of the SQLite database (`porthole.db`: tokens and port reservations) and, in mode `acme`, of `certs/`; must be writable by the service user |
| `ssh_gateway.listen` | `PORTHOLED_SSH_LISTEN` | off | Address of the SSH gateway, for example `:2222` (see [SSH gateway](#ssh-gateway)) |
| `ssh_gateway.max_conns_per_tunnel` | - | `256` | Concurrent SSH channels per tunnel |
| `trust_proxy_headers` | `PORTHOLED_TRUST_PROXY_HEADERS` | `false` | Take visitor IP addresses from `X-Forwarded-For`; enable only behind a proxy you control |
| `max_tunnels_per_client` | `PORTHOLED_MAX_TUNNELS_PER_CLIENT` | `10` | Simultaneous tunnels for tokens without a limit of their own |
| `shutdown_grace` | - | `10s` | How long graceful shutdown (SIGINT/SIGTERM) may take before connections are cut |

## Firewall

Open TCP 443 (control connections and HTTP tunnels), TCP 80 in mode `acme` (HTTP-01 challenge and redirect), the TCP port range for TCP tunnels, and the SSH gateway port
(for example 2222) if you enable it.

## Run it

With the deb or rpm package the unit and the `porthole` user already exist and the example configuration is installed
as `/etc/porthole/portholed.yaml`: edit it as above, then

```console
$ sudo systemctl enable --now portholed
$ sudo systemctl status portholed
```

Without a package, run it by hand (or install the unit [deploy/portholed.service](../deploy/portholed.service)
yourself, see the comments in it) or use a container image (see [Docker](#docker)):

```console
$ portholed serve --config /etc/porthole/portholed.yaml
```

`portholed serve` takes `--log-level` (`debug`, `info`, `warn` or `error`; default `info`).

## Tokens

Create one token per client machine; the name becomes the client name in the public URLs:

```console
$ sudo -u porthole portholed token create --name home
```

The token is shown once (the server stores only a hash), together with a ready-to-use `porthole login` command. The
`token` commands read the same configuration and database as `serve` (use `--config` if it is not at
`/etc/porthole/portholed.yaml`) and work while the server is running. Run them as the user the service runs as
(`sudo -u porthole` above): a database created by root cannot be opened by the service. Under Docker, use
`docker exec` as shown in [Installation](install.md#docker). Token names are 1-32 characters of `a-z`, `0-9` and `-`.
More options (without the `sudo -u porthole` prefix):

```console
$ portholed token create --name office-nas --expires 30d --scopes tunnel:http,tunnel:tcp --max-tunnels 5
$ portholed token list            # --all includes revoked tokens, --json prints a JSON array
$ portholed token revoke home     # by id or name; takes effect on live sessions
```

| Flag of `token create` | Meaning |
|---|---|
| `--name` | Client name, required; becomes part of tunnel URLs |
| `--expires` | Lifetime: `30d`, `720h` or `0` for no expiry (default `0`) |
| `--scopes` | Comma-separated scopes (default `tunnel:http,tunnel:tcp,tunnel:udp`) |
| `--max-tunnels` | Maximum simultaneous tunnels (`0`: the server default `max_tunnels_per_client`) |

A token is a client identity: every client sees and manages only its own tunnels and names. Tokens are 256-bit
secrets stored only as hashes; authorization is re-checked on every tunnel registration and revocation applies to live
sessions. A token of one client can also be given the scope `connect:<client>`, which lets its holder pass the
[private SSH gateway](ssh.md#public-and-private-machines) of that client without owning it. `portholed token revoke`
also deletes the client's [port reservations](#tcp-ports-and-reservations).

## TCP ports and reservations

TCP tunnels (and SSH tunnels in `--public-port` mode) get a port from `tcp_port_range`; `porthole tcp 5432
--remote-port 20017` asks for a specific one. The port is reserved for the pair (client, tunnel name): when the tunnel
goes away, the reservation is kept for 24 hours, so a reconnecting client gets the same address. Reservations are
stored in the SQLite database, so they survive a server restart or crash (the 24 hours then start at the restart). A
changed `tcp_port_range` ignores reservations outside the new range. See [ADR 0003](adr/0003-ssh-gateway-and-port-reservations.md).

## Behind a reverse proxy

`portholed` can run in plain HTTP on loopback behind a proxy that terminates TLS and handles the wildcard certificate.
Set `tls.mode: off`, bind to loopback and trust the proxy's `X-Forwarded-For`:

```yaml
version: 1
domain: tun.example.com
listen: "127.0.0.1:8080"
tls:
  mode: off
trust_proxy_headers: true
tcp_port_range: "20000-29999"
data_dir: /var/lib/porthole
```

[deploy/Caddyfile.example](../deploy/Caddyfile.example) is a ready Caddy configuration (wildcard certificate via DNS-01,
which needs a DNS provider module compiled into Caddy; WebSocket upgrades and unbuffered streaming responses are
handled). Enable `trust_proxy_headers` only when `portholed` is reachable exclusively through that proxy; otherwise
visitors can spoof their address. TCP and SSH tunnels do not pass through the proxy: `portholed` listens on the ports
of `tcp_port_range` (and on the SSH gateway port) directly, so open them in your firewall.

### Behind Traefik or Dokploy (TLS passthrough)

A proxy that owns ports 80 and 443 but cannot issue a wildcard certificate (Traefik without a DNS-01 provider, the
default in Dokploy) can instead pass the TLS connection through by SNI and leave certificates to `portholed`
(mode `acme`): a Traefik TCP router with ``HostSNI(`tun.example.com`)`` and a `HostSNIRegexp` for
`*.tun.example.com`, `tls.passthrough=true`, forwarding to the HTTPS port of the container, plus plain HTTP routers for
the same hosts forwarding to `http_listen` (HTTP-01 and the redirect). TCP and SSH tunnel ports are published
directly. [deploy/dokploy-compose.yaml](../deploy/dokploy-compose.yaml) is a ready compose file: in Dokploy create a
Compose service, choose Raw and paste it, then set `PORTHOLED_DOMAIN` and your domain in the labels.

## Docker

See [Installation: Docker](install.md#docker) for a `docker run` example with a certificate mounted from
`/etc/letsencrypt`.

### Docker Compose

[deploy/compose.yaml](../deploy/compose.yaml) builds the image from source and runs it read-only, as a non-root user,
without capabilities. From the repository root:

```console
$ cp deploy/portholed.example.yaml deploy/portholed.yaml        # then set the domain and the TLS mode
$ docker compose -f deploy/compose.yaml up -d --build
$ docker compose -f deploy/compose.yaml exec portholed portholed token create --name home
```

With the default `acme` mode the example publishes ports 80 and 443 and keeps the certificates in the data volume. For
mode `files` mount the certificates as `deploy/tls/fullchain.pem` and `deploy/tls/privkey.pem`, readable by uid 65532.
The example publishes a small port range (`20000-20099`, kept in sync with `PORTHOLED_TCP_PORT_RANGE`, because publishing
thousands of ports is slow with the default Docker networking) and the SSH gateway on `2222` (`PORTHOLED_SSH_LISTEN`).

## SSH gateway

The SSH gateway lets people reach a machine behind NAT by name with stock OpenSSH, through the server as a jump host
(`ssh -J tun.example.com:2222 user@home`); see [SSH by name](ssh.md) for the user's view. It is off unless
`ssh_gateway.listen` is set:

```yaml
ssh_gateway:
  listen: ":2222"
  max_conns_per_tunnel: 256
```

or `PORTHOLED_SSH_LISTEN=:2222`. Open that port in the firewall (port 22 of the VPS belongs to its own sshd).

- The gateway is not a shell: it accepts only `direct-tcpip` channels and refuses sessions, `exec`, `tcpip-forward`,
  agent and X11 forwarding, so logging in to the server through it is impossible, and it never sees the SSH plaintext
  between the visitor and the target machine.
- On first start it creates an ed25519 host key, `<data_dir>/ssh_host_ed25519_key` (mode 0600), and logs its SHA256
  fingerprint. `portholed ssh-hostkey` prints the fingerprint again (it reads the same `--config`). Give the
  fingerprint to your users so they can compare it on their first connection. Back up the key file or the clients'
  `known_hosts` entries break when it is lost.
- Limits: a handshake deadline of 10 s, failed authentication rate-limited per source IP, at most
  `max_conns_per_tunnel` concurrent channels per tunnel, idle connections without channels closed after 60 s.
- Without a gateway, a plain `porthole ssh` falls back to a public TCP port with a warning.

Design and rejected alternatives: [ADR 0003](adr/0003-ssh-gateway-and-port-reservations.md).

## Command reference

| Command | Purpose |
|---|---|
| `portholed serve [--config] [--log-level]` | Run the server |
| `portholed token create --name N [--expires 30d] [--scopes ...] [--max-tunnels N]` | Create a token |
| `portholed token list [--all]` | List tokens |
| `portholed token revoke <id\|name>` | Revoke a token |
| `portholed ssh-hostkey` | Print the fingerprint of the SSH gateway host key |
| `portholed version` | Print the version |

The global flag `-c, --config` (default `/etc/porthole/portholed.yaml`; empty means environment variables only)
applies to all of them.

### Machine-readable output (`--json`)

The global flag `--json` makes a command write JSON to stdout instead of text (one document per command):

| Command | Document |
|---|---|
| `token create` | `id`, `name`, `token` (the secret: this is the only place that ever shows it), `last4`, `scopes`, `max_tunnels`, `created_at`, `expires_at`, `server_url`, `login` (the `porthole login ...` command line) |
| `token list` | An array of tokens, without secrets |
| `token revoke` | `id`, `name`, `revoked`, `already_revoked` |
| `ssh-hostkey` | `fingerprint`, `path` |
| `version` | `name`, `version`, `go`, `os`, `arch` |

`serve` writes nothing to stdout; its log is always JSON on stderr. A failure writes
`{"error":{"code":"...","message":"..."}}` to stdout (without `--json`: `portholed: <message>` to stderr).

### Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Any other failure: database, a token that does not exist, the server stopping with an error |
| 2 | Usage error: unknown command, bad flag or argument, an invalid `--name`, `--expires`, `--scopes` or `--log-level` |
| 78 | The configuration could not be loaded or is invalid |

The client-side statuses 3 to 6 are not used by `portholed`; see the [client guide](client.md#exit-status).

## Security

Please report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md), not in public issues. The
security model is described in [DESIGN.md](../DESIGN.md#4-security-model).
