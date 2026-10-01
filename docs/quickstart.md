# Quick start

porthole is a self-hosted, open-source alternative to ngrok: you run the server, `portholed`, on a VPS with your own
domain, and the client, `porthole`, on any machine behind NAT. To expose a local port: 1) install `portholed` on the VPS
and point `tun.example.com` and `*.tun.example.com` at it; 2) run `portholed join create --name home` on the server and
`porthole join <link>` on your machine; 3) run `porthole http 3000`, which prints a public HTTPS address such as
`https://http-3000-home.tun.example.com`.

This guide shows you how to:

- Install `portholed` on a server with a public IP address and point your domain at it
- Start the server, which gets an HTTPS certificate for every tunnel by itself
- Enrol a machine behind NAT with a one-time join link
- Publish a local web service at a public HTTPS address

<details>
<summary><strong>The short version</strong></summary>

```console
# On the server
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server
$ sudoedit /etc/porthole/portholed.yaml                    # set "domain"
$ sudo systemctl enable --now portholed
$ sudo -u porthole portholed join create --name home       # prints a one-time `porthole join` command

# On your machine, behind NAT
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
$ porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...
$ porthole http 3000
connected as home
https://http-3000-home.tun.example.com -> 127.0.0.1:3000
```

DNS records for `tun.example.com` and `*.tun.example.com` must point at the server first, and ports 80, 443 (and 2222
for SSH by name) must be open.

</details>

## Two machines, two roles

porthole has two programs. You set up each on a different machine:

| | Server (VPS) | Client (behind NAT) |
|---|---|---|
| Program | `portholed` | `porthole` |
| Where | A machine with a public IP address and a domain you control | Any machine whose services you want to publish: a laptop, a home server, a Raspberry Pi |
| Needs | Open ports, a domain | Only an outbound connection to the server on port 443 |
| Steps | 1 to 4 below | 5 below |

If someone else runs the server for you, skip to [step 5](#5-connect-the-machine-and-open-a-tunnel) and ask them for a
join link.

## Prerequisites

For the server:

- A **Linux VPS with a public IP address**. Debian, Ubuntu, Fedora and RHEL derivatives get a package with a systemd
  unit; other systems get the binary or a [Docker image](install.md#docker).
- A **domain with wildcard DNS**: an `A` record for `tun.example.com` and one for `*.tun.example.com`, both pointing at
  the server. The examples on this page use `tun.example.com`.
- **Open ports**: `80` and `443` (certificates and all web tunnels), `2222` (the optional SSH gateway) and a TCP port
  range, `20000-29999` by default, for TCP tunnels.
- An **email address** (optional): Let's Encrypt can use it to warn you before a certificate expires.

For the client you need nothing but the server's address and a join link.

## 1. Install the server

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server
```

On Debian, Ubuntu, Fedora and RHEL (as root or with `sudo`) this installs the `.deb` or `.rpm`: the `portholed`
binary, the systemd unit, the `porthole` system user and an example configuration at `/etc/porthole/portholed.yaml`.
It checks the SHA-256 of the download first. Nothing is started yet.

> Prefer containers? Use [Docker Compose or Dokploy](deploy.md) instead of this step and the next two. Other install
> options (archives, packages, verifying a download) are in [Installation](install.md).

## 2. Point the domain and set it in the configuration

Create the two DNS records from [Prerequisites](#prerequisites), then edit the configuration:

```console
$ sudoedit /etc/porthole/portholed.yaml
```

The only line you have to change is `domain`:

```yaml
version: 1
domain: tun.example.com
```

That is all for TLS. The default mode, `acme`, gets a certificate per tunnel host name from Let's Encrypt at the first
connection to it, and renews it in the background; there is no DNS provider to configure and no renewal job
([ADR 0004](adr/0004-automatic-https-per-tunnel.md)). Add `tls.acme.email` if you want expiry notices. If you already have a wildcard certificate, or a
reverse proxy in front, see [TLS](server.md#tls) and [Behind a reverse proxy](server.md#behind-a-reverse-proxy).

To enable SSH by name, add the gateway to the same file:

```yaml
ssh_gateway:
  listen: ":2222"
```

Open the ports on the firewall of the server (see [Firewall](server.md#firewall)).

## 3. Start the server

```console
$ sudo systemctl enable --now portholed
$ sudo systemctl status portholed
```

The log is JSON on stderr; read it with `journalctl -u portholed`. If the service does not start, look there
first (a configuration file with an unknown key is rejected).

## 4. Create a join link

A join link gives one machine its own permanent token without anyone copying a secret around. It works once and
expires after 15 minutes:

```console
$ sudo -u porthole portholed join create --name home
Join link for "home" (id 3kq9w2m1z8xa), valid until 2026-10-01 12:15 UTC and usable once.

On the machine, run:

    porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...
```

`home` is the client name. It becomes part of the tunnel addresses (`https://<tunnel>-home.tun.example.com`) and the
name you use for SSH. Use one name per machine. More options (`--ttl`, `--scopes`, `--max-tunnels`) are in
[Join links](server.md#join-links); for scripted setups there are [tokens](server.md#tokens).

## 5. Connect the machine and open a tunnel

On the machine behind NAT, install the client and redeem the link:

```console
$ curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
$ porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...
joined as home
```

Now publish a local web service, for example something listening on port 3000:

```console
$ porthole http 3000
connected as home
https://http-3000-home.tun.example.com -> 127.0.0.1:3000
```

Open the address in a browser. You see your local service with a valid HTTPS certificate: the first request to a new
name waits a few seconds while the server obtains the certificate, later ones do not. The command stays in the
foreground and reconnects by itself when the network drops; press `Ctrl-C` to close the tunnel. The address is stable:
the default name is `http-<port>`, or choose your own with `--name blog`
(`https://blog-home.tun.example.com`).

Something does not work? See [Troubleshooting](troubleshooting.md).

## Next steps

- [Recipes](recipes.md): webhooks, SSH home, Postgres, several tunnels, a service on another machine
- [SSH by name](ssh.md): `ssh -J tun.example.com:2222 alice@home`, with nothing installed on the machine you connect from
- [Run the client as a service](client.md#run-the-client-as-a-service): tunnels that survive reboots (`tunnels.yaml` and the daemon)
- [Managing porthole with an LLM agent](agents.md): MCP for the server and for the machine
- [Deployment](deploy.md): Docker Compose, Dokploy, behind another reverse proxy
- [FAQ](faq.md)
