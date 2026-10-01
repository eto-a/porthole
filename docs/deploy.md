# Deployment

Four ways to run the server, `portholed`. Pick the one that fits the machine; the configuration, the DNS records and
the client side are the same everywhere.

| Setup | Use it when | TLS |
|---|---|---|
| [systemd (deb and rpm)](#systemd-deb-and-rpm) | A VPS of your own with nothing else on ports 80 and 443 | `portholed` gets certificates itself |
| [Docker Compose](#docker-compose) | You prefer containers, again with ports 80 and 443 free | `portholed` gets certificates itself |
| [Dokploy](#dokploy) | The ports are owned by Traefik of a Dokploy server | Traefik passes TLS through, `portholed` gets certificates |
| [Behind another reverse proxy](#behind-another-reverse-proxy) | Caddy, nginx or another proxy already serves your sites | The proxy terminates TLS |

Common to all of them:

- **DNS.** `tun.example.com` and `*.tun.example.com` point at the server ([DNS](server.md#dns)).
- **Ports.** `443` and `80` (HTTPS and certificates), the TCP range of `tcp_port_range` and, for SSH by name,
  `2222`. TCP and SSH tunnel ports always go to `portholed` directly, never through a proxy ([Firewall](server.md#firewall)).
- **State.** Keep the data directory (`/var/lib/porthole`). It holds the token database, the port reservations, the SSH
  gateway host key and the certificates; losing it means new certificates (Let's Encrypt limits apply, see
  [Certificate is not issued](troubleshooting.md#the-certificate-is-not-issued)) and a host-key warning for every SSH user.

## systemd (deb and rpm)

The package is what `install.sh --server` installs on Debian, Ubuntu, Fedora and RHEL derivatives, and you can also
download it from the [releases](https://github.com/eto-a/porthole/releases) ([Installation](install.md#packages-debian-ubuntu-fedora-rhel-and-derivatives)):

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server
$ sudoedit /etc/porthole/portholed.yaml        # set "domain"; see Server setup
$ sudo systemctl enable --now portholed
$ journalctl -u portholed -f
```

The package installs the binary in `/usr/bin`, the unit `portholed.service`, the user `porthole`, the directory
`/var/lib/porthole` and an example configuration in `/etc/porthole/portholed.yaml`. It does not start the service,
because the domain has to be set first. The unit runs as `porthole`, binds ports below 1024 through a capability
instead of root, and is hardened (read-only system, private `/tmp`; [deploy/portholed.service](../deploy/portholed.service)).
`systemctl reload portholed` re-reads the TLS certificate files (mode `files`); it reloads nothing else, so restart the
service after changing other settings.

Commands that talk to the running server, such as `portholed join create` and `portholed token create`, must run as
the service user: `sudo -u porthole portholed join create --name home`. Without a package, the header of the unit file
lists the manual steps (`useradd`, `install`, `systemctl enable --now`).

## Docker Compose

[deploy/compose.yaml](../deploy/compose.yaml) runs the server read-only, as a non-root user and without Linux
capabilities. From a checkout of the repository:

```console
$ cp deploy/portholed.example.yaml deploy/portholed.yaml     # set "domain" (and the TLS mode if you want files)
$ docker compose -f deploy/compose.yaml up -d --build
$ docker compose -f deploy/compose.yaml exec portholed portholed join create --name home
```

The file publishes `443`, `80` (certificates and the redirect to `https://`), the TCP range `20000-20099` and the SSH
gateway port `2222`, and keeps the certificates in the `porthole-data` volume. The range is deliberately small because
publishing thousands of ports is slow with the default Docker networking; if you change it, change
`PORTHOLED_TCP_PORT_RANGE` to match. To use the published image instead of building from source, replace the `build:`
block with `image: ghcr.io/eto-a/porthole/portholed:<version>` ([Docker](install.md#docker)). With your own wildcard
certificate, see [Docker Compose](server.md#docker-compose) for the `files` mode.

## Dokploy

[Dokploy](https://dokploy.com) runs its own Traefik on ports 80 and 443. Traefik cannot get a wildcard certificate
without a DNS provider, so [deploy/dokploy-compose.yaml](../deploy/dokploy-compose.yaml) does not let it terminate TLS
for the tunnel hosts: Traefik passes the TLS connection through by host name, and `portholed` gets one certificate per
name from Let's Encrypt itself. This was tested on a live Dokploy server.

1. **DNS.** Add `A` records for `tun.example.com` and `*.tun.example.com` that point at the server running Dokploy.
2. **Create the service.** In the Dokploy UI choose *Create Project*, open it and add a service of type *Compose*, and choose
   *Raw* as its source.
3. **Paste the file.** Paste the content of [deploy/dokploy-compose.yaml](../deploy/dokploy-compose.yaml). Replace
   `tun.example.com` with your domain in `PORTHOLED_DOMAIN` and in the Traefik labels (the three rules: the apex, the
   wildcard and the plain HTTP router).
4. **Narrow the trusted proxies.** `PORTHOLED_TRUSTED_PROXIES` lists the addresses that may send PROXY protocol headers
   (see below). The default covers the usual Docker private ranges; replace it with the subnet that
   `docker network inspect dokploy-network` shows.
5. **Open the ports.** `2222` (SSH gateway) and the TCP range `20000-20099` are published by the compose file directly
   on the host, not through Traefik. Open them in the firewall of the server.
6. **Deploy.** Deploy the service. Then create the first join link in the container; the image has no shell, so run
   the binary directly (the container name is shown under *Logs* in Dokploy):

   ```console
   $ docker exec -it <container> /usr/local/bin/portholed join create --name home --config ""
   ```

   Give the printed `porthole join` command to the machine ([Quick start](quickstart.md#5-connect-the-machine-and-open-a-tunnel)).

Keep the `porthole-data` volume across redeployments: it holds the certificates, and a fresh volume orders new ones. To
test without touching the Let's Encrypt production limits, uncomment `PORTHOLED_ACME_CA` (the staging URL is in the
file); staging certificates are not trusted by browsers.

### Why TLS passthrough

A tunnel host such as `blog-home.tun.example.com` is a name under your wildcard. With passthrough, Traefik reads only
the server name that the browser sends in the clear at the start of the TLS handshake (SNI) and forwards the still
encrypted connection to `portholed`: a TCP router with `HostSNI` for the apex and `HostSNIRegexp` for the subdomains and
`tls.passthrough=true`. The plain HTTP routers forward the same hosts to port 80 of the container, which serves the
Let's Encrypt HTTP-01 challenge and the redirect to `https://`. The TCP routers need Traefik v3 (the Dokploy default).

### Why the PROXY protocol

Because Traefik forwards a raw TCP connection, `portholed` would see Traefik's address as the peer of every visitor
and every client, and the per-address rate limits, the request log and the audit log would all show that one address.
There is no `X-Forwarded-For` either, because the proxy never reads the encrypted HTTP. So Traefik announces the real
address with a small PROXY protocol v2 header in front of the stream (the `proxyProtocol.version=2` label), and
`portholed` reads it, but only from the addresses in `trusted_proxies` (`proxy_protocol: true` without that list is a
configuration error). A connection from a trusted proxy must carry the header; one from anywhere else must not, so a
visitor cannot choose its own address. Details and the limits are in
[Behind Traefik or Dokploy](server.md#behind-traefik-or-dokploy-tls-passthrough). Leave `trust_proxy_headers` off in
this setup.

## Behind another reverse proxy

If Caddy, nginx or another proxy already owns ports 80 and 443 and terminates TLS with a wildcard certificate, run
`portholed` in plain HTTP on loopback:

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

The proxy must forward the `Host` header and `X-Forwarded-For`, support WebSocket upgrades (the control connection of
every client is one) and not buffer responses. [deploy/Caddyfile.example](../deploy/Caddyfile.example) is a complete
Caddy configuration; the wildcard certificate needs a DNS-01 provider module compiled into Caddy. Enable
`trust_proxy_headers` only when `portholed` is reachable exclusively through the proxy, or visitors can fake their
address. TCP and SSH tunnels bypass the proxy: open their ports in the firewall. Full explanation, including the choice
between `X-Forwarded-For` and the PROXY protocol: [Behind a reverse proxy](server.md#behind-a-reverse-proxy).
