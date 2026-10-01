# Expose a local service to the internet: guides

Task-oriented answers for people who search "how do I put this on the internet". All of them use your own porthole server (`portholed`, see the [Quick start](quickstart.md)) and a machine enrolled with `porthole join <link>`; the examples use the domain `tun.example.com` and the client name `home`. More commands, with explanations, are in [Recipes](recipes.md); questions about safety, domains and IPv6 are in the [FAQ](faq.md).

- [Expose localhost or a local website](#expose-localhost-or-a-local-website)
- [Receive webhooks on a development server](#receive-webhooks-on-a-development-server)
- [SSH into a home server behind NAT or CGNAT](#ssh-into-a-home-server-behind-nat-or-cgnat)
- [Publish a database or a game server over TCP](#publish-a-database-or-a-game-server-over-tcp)
- [Reach a NAS or Home Assistant on your home network](#reach-a-nas-or-home-assistant-on-your-home-network)
- [Let an AI agent such as Claude Code open tunnels](#let-an-ai-agent-such-as-claude-code-open-tunnels)
- [Keep tunnels up after a reboot](#keep-tunnels-up-after-a-reboot)

## Expose localhost or a local website

Run `porthole http <port>` on the machine where the site runs; it publishes it at an HTTPS address on your domain.

```console
$ porthole http 3000
connected as home
https://http-3000-home.tun.example.com -> 127.0.0.1:3000
```

Pick the name yourself with `--name blog` (`https://blog-home.tun.example.com`). HTTPS and WebSocket work, and the certificate is issued by the server automatically at the first request. The command reconnects by itself if the network drops, and Ctrl-C closes the tunnel. Details: [Client guide: Expose a service](client.md#expose-a-service).

## Receive webhooks on a development server

Give the sender of the webhook a stable HTTPS URL that ends on your laptop, and let the server keep what it sends so that you can look at it and send it again.

```console
$ porthole http 3000 --name hooks --inspect
https://hooks-home.tun.example.com -> 127.0.0.1:3000
```

Paste `https://hooks-home.tun.example.com/<your path>` into the settings of the service that sends the webhook. The name is fixed, so the URL stays the same after a restart. `--inspect` is opt-in: the server stores headers and the first 64 KiB of every request and response body in memory (`Authorization` and cookies are stored as `REDACTED`), and the operator or an AI agent can read them and replay a request into your service. Details: [Recipes](recipes.md#receive-webhooks-on-your-laptop) and [Request log and inspection](server.md#request-log-and-inspection).

## SSH into a home server behind NAT or CGNAT

On the home machine run `porthole ssh`; from anywhere run `ssh -J tun.example.com:2222 alice@home`. The home machine only makes an outbound connection to your server, so it needs no port forwarding on the router and no public address of its own.

```console
$ porthole ssh                                  # on the home machine, which has an sshd
$ ssh -J tun.example.com:2222 alice@home        # on any machine with OpenSSH
```

For a short `ssh home`, add this to `~/.ssh/config` of the machine you connect from:

```
Host home
    HostName home
    User alice
    ProxyJump tun.example.com:2222
```

The server needs the SSH gateway (`ssh_gateway.listen: ":2222"`, port 2222 open). With `porthole ssh --private` the gateway also asks for a porthole token. Details: [SSH by name](ssh.md).

## Publish a database or a game server over TCP

Run `porthole tcp <port>`; the service becomes reachable at `tun.example.com:<public port>`, a port from the server's range.

```console
$ porthole tcp 5432 --remote-port 20017         # tun.example.com:20017
$ porthole tcp 25565                            # any free port of the range; the address is printed
$ porthole tcp nas.local:5432                   # a service on another machine of your network
```

Without `--remote-port` the server picks a free port and keeps it reserved for you for 24 hours. The port is open to everyone on the internet, so use the strong passwords and TLS of the service itself; for a database that only you use, forward its port over the SSH tunnel instead ([Recipes](recipes.md#postgres-or-any-tcp-service-on-a-fixed-port)). The server's firewall must allow the port range (`tcp_port_range`, default `20000-29999`).

## Reach a NAS or Home Assistant on your home network

Run the client on any machine of the same network and give it the address of the device: `porthole http host:port`. Nothing has to be installed on the device itself.

```console
$ porthole http 192.168.1.20:8123 --name ha
https://ha-home.tun.example.com -> 192.168.1.20:8123
```

Replace the address and the port with those of your NAS, Home Assistant or any other web interface. A bare port means `127.0.0.1`, a `host:port` is dialled from the machine that runs `porthole`. The page is then public: use the login of the application, and check its documentation for the settings it needs behind a reverse proxy. For a raw TCP service use `porthole tcp host:port` the same way. To keep it up after a reboot, put it in `tunnels.yaml` (see below). More: [Recipes](recipes.md#a-docker-service-on-another-machine-of-your-network).

## Let an AI agent such as Claude Code open tunnels

Add porthole as an MCP server: `claude mcp add porthole-local -- porthole mcp` lets an agent open and close tunnels of the machine it runs on, and the server's endpoint lets an operator agent ask a connected machine for a tunnel.

```console
$ claude mcp add porthole-local -- porthole mcp
$ claude mcp add --transport http porthole https://tun.example.com/_porthole/mcp \
    --header "Authorization: Bearer ph_..."
```

Then say "pass me port 8080 from home". The machine decides what may be exposed (`allow_remote` in its tunnels file), the token of the agent has only the scopes you gave it, and `--read-only` leaves nothing that changes anything. Details: [Managing porthole with an LLM agent](agents.md) and [Recipes](recipes.md#agent-open-a-tunnel-for-me).

## Keep tunnels up after a reboot

List the tunnels in `/etc/porthole/tunnels.yaml` and enable the client service of the deb or rpm package:

```yaml
version: 1
tunnels:
  blog: {type: http, addr: 3000}
  db:   {type: tcp, addr: "nas.local:5432"}
  ssh:  {type: ssh}
```

```console
$ sudo systemctl enable --now porthole
$ porthole status
```

Details, including the user unit and the credentials file: [Run the client as a service](client.md#run-the-client-as-a-service) and [Recipes](recipes.md#several-tunnels-that-survive-reboots).
