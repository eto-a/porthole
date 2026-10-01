# FAQ

Short answers about porthole, a self-hosted, open-source alternative to ngrok. Practical task guides are in [Guides](guides.md), ready commands in [Recipes](recipes.md).

## How do I expose localhost to the internet with my own server?

Run `porthole http 3000` on the machine that has the service; it prints a public HTTPS address such as `https://http-3000-home.tun.example.com`. You need your own server running `portholed` (a VPS with a public IP address and a domain) and one join link to enrol the machine: `porthole join <link>`. The whole path, from an empty VPS to a public address, is in the [Quick start](quickstart.md); the commands are in the [Client guide](client.md#expose-a-service).

## Is porthole a self-hosted alternative to ngrok?

Yes: `porthole http 8080` does for your own server what the ngrok agent does for the hosted ngrok service. You run the server, `portholed`, under your own domain; there is no public instance, no usage limit set by a third party and no account with one. Every HTTP tunnel gets its own HTTPS certificate automatically. Details: [Server setup](server.md).

## How is porthole different from frp and cloudflared?

Simplified from the public documentation of those tools; check it before deciding. No performance claims are made here.

- **frp** is also self-hosted, with `frps` and `frpc`. porthole's defaults differ: tunnels are configured on the client and the server only issues tokens, every HTTP tunnel gets automatic HTTPS, machines are enrolled with one-time join links, and SSH by name works with stock OpenSSH.
- **cloudflared** connects your machine to the Cloudflare network, so the server side is Cloudflare's, and for SSH its documentation has the visiting side run `cloudflared` or WARP. With porthole the connecting side needs only `ssh -J`.

When to choose which, including ngrok and sish: [How it compares](../README.md#how-it-compares) in the README.

## How do I SSH into a computer behind NAT?

On the computer run `porthole ssh`; from anywhere else run `ssh -J tun.example.com:2222 alice@home`, where `home` is the name of the machine. It works with stock OpenSSH on the connecting side and needs no public port on the target, even behind NAT. The server must have the SSH gateway enabled (`ssh_gateway.listen: ":2222"`). Details: [SSH by name](ssh.md); the private variant, which asks for a token, is in [Public and private machines](ssh.md#public-and-private-machines).

## Do I need a domain?

Yes. Set `domain: tun.example.com` in `portholed.yaml` and create an `A` record for it and a wildcard record `*.tun.example.com`, because every HTTP tunnel is a subdomain (`https://<tunnel>-<client>.tun.example.com`). A subdomain of a domain you already own is enough; you do not need to move the whole domain. See [DNS](server.md#dns).

## Can I use porthole without my own server?

No. porthole is self-hosted only: install `portholed` on a machine with a public IP address (`curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server`; the [Quick start](quickstart.md) has the rest). If someone else runs a server for you, you only install the client and use the join link they give you ([Client guide](client.md#join-with-a-link)).

## Can Claude Code or another AI agent manage my tunnels?

Yes, through MCP. On a machine with the client daemon run `claude mcp add porthole-local -- porthole mcp`: the agent can then open, close and list tunnels of that machine. On the server, `claude mcp add --transport http porthole https://tun.example.com/_porthole/mcp --header "Authorization: Bearer ph_..."` gives an agent a token-scoped view of clients, tunnels, traffic and the audit log, and lets it ask a connected machine to open a tunnel. There is a `--read-only` mode, and the model never receives a long-lived secret. See [Managing porthole with an LLM agent](agents.md); agents without MCP can use the `--json` output of the CLI.

## Is porthole safe to use?

It is in alpha: the configuration format, the wire protocol and the CLI may still change before a stable release ([Status](../README.md#status)). Today a client authenticates with a token that is stored on the server only as a hash, can expire and be revoked at once, and has scopes and a tunnel limit ([Tokens](server.md#tokens)); a join link works once and expires after 15 minutes by default ([Join links](server.md#join-links)); the SSH gateway only forwards and gives no shell; releases are signed ([Verifying a download](install.md#verifying-a-download)). Keep in mind that tunnel host names are published in public Certificate Transparency logs, that a public TCP tunnel port is open to everyone, and that a published service is only as safe as the service itself. The security model is in [DESIGN.md](../DESIGN.md#4-security-model); report vulnerabilities privately ([SECURITY.md](../SECURITY.md)).

## Is my traffic visible to the server?

For HTTP tunnels yes, for SSH through the gateway no. TLS of an HTTP tunnel ends on your server (it routes by `Host`), which records only metadata (time, tunnel, visitor IP, method, host, path, status, sizes) in memory, and headers and bodies only for a tunnel started with `porthole http 3000 --inspect`; the operator can forbid that with `traffic.allow_inspect: false` ([Request log and inspection](server.md#request-log-and-inspection)). The SSH gateway forwards ciphertext of a session that is encrypted end to end with the target's sshd ([how it works](ssh.md#how-it-works)). For other TCP tunnels the server relays bytes without interpreting them: if the service speaks TLS itself, the server sees only ciphertext. It is your own server, but do not use a server you do not trust.

## Which protocols does porthole support?

HTTP(S) with WebSocket (`porthole http`), TCP (`porthole tcp 5432`, optionally with `--remote-port 20017`) and SSH (`porthole ssh`). UDP is not supported yet. Overview: [Client guide](client.md#expose-a-service).

## Does porthole run on Windows and macOS?

The client does: `porthole` archives exist for Linux, macOS and Windows on amd64 and arm64 ([Archives](install.md#archives)), and `install.sh` covers Linux and macOS. On macOS and Windows there are no service definitions yet, so run `porthole daemon` yourself ([Client guide](client.md#macos-and-windows)). The server is meant for Linux, with deb and rpm packages, a systemd unit and a Docker image ([Deployment](deploy.md)).

## How many tunnels can I have?

By default 10 at once per client (`max_tunnels_per_client`), or the limit of its token (`portholed token create --name home --max-tunnels 5`). The SSH gateway allows 256 concurrent sessions per tunnel (`ssh_gateway.max_conns_per_tunnel`), and TCP tunnels share the port range `tcp_port_range` (`20000-29999` by default). See the [configuration table](server.md#configuration).

## What happens when the connection drops?

The client reconnects by itself. The first connection gives up after 5 attempts (`--max-initial-attempts 0` retries forever); once connected, it keeps trying. HTTP addresses are derived from the tunnel name, so they are the same after a restart, and a TCP port stays reserved for the client and tunnel name for 24 hours, also across a server restart ([reservations](server.md#tcp-ports-and-reservations)). To keep tunnels up across reboots, run the daemon (`sudo systemctl enable --now porthole`; [Run the client as a service](client.md#run-the-client-as-a-service)).

## Can I use my own domain name for a tunnel?

Not today: tunnel hosts are always under the domain of the server, and per-tunnel custom domains were left out on purpose ([ADR 0004](adr/0004-automatic-https-per-tunnel.md)). Choose a stable tunnel name instead, for example `porthole http 3000 --name blog`, which gives `https://blog-home.tun.example.com`.

## Does porthole support IPv6?

It is not tested and not documented, so do not rely on it. From the code: the server listens with Go's `net.Listen("tcp", ...)` on the configured address (`:443` by default; `internal/server/server.go`) and on the TCP tunnel ports with an empty `tcp_bind_host` (`internal/server/registry.go`), which for a wildcard address is dual-stack on most systems (Go's behaviour, not tested here), and the systemd unit allows `AF_INET6`. There are no IPv6 tests, and nothing in these documents has been verified with `AAAA` records, certificate issuance over IPv6 or an IPv6-only client. If you try it, share the result (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## Is there a web interface?

No. The server is managed with the commands `portholed token`, `join` and `admin`, with the admin API, and by AI agents through MCP; the client has `porthole status` and `--json` output. The request log and the recorded requests of an `--inspect` tunnel, including replay, are available through the admin API and the MCP tools ([Agents](agents.md)).

## Why are there two programs?

`portholed` is the server and `porthole` is the client: they run on different machines with different needs, as with frps and frpc or tailscaled and tailscale. The server side has the configuration, the database and the ports; the client side only opens one outbound connection (port 443) and works behind NAT.

## What is the license?

Apache-2.0 ([LICENSE](../LICENSE)). The source is on [GitHub](https://github.com/eto-a/porthole); see [CONTRIBUTING.md](../CONTRIBUTING.md) to contribute.
