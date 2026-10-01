# Recipes

Ready-to-use commands for common jobs. They assume the server `tun.example.com` is running ([Quick start](quickstart.md)) and that your machine is enrolled as `home` (`porthole join <link>`). Replace the names with yours. Every flag is described in the [Client guide](client.md) and the [Server setup](server.md).

- [Receive webhooks on your laptop](#receive-webhooks-on-your-laptop)
- [SSH to a machine at home, by name](#ssh-to-a-machine-at-home-by-name)
- [Private SSH](#private-ssh)
- [Postgres or any TCP service on a fixed port](#postgres-or-any-tcp-service-on-a-fixed-port)
- [Several tunnels that survive reboots](#several-tunnels-that-survive-reboots)
- [A Docker service on another machine of your network](#a-docker-service-on-another-machine-of-your-network)
- ["Agent, open a tunnel for me"](#agent-open-a-tunnel-for-me)
- [Several machines](#several-machines)

## Receive webhooks on your laptop

Give the webhook sender a stable HTTPS address that ends on your development server:

```console
$ porthole http 3000 --name hooks
connected as home
https://hooks-home.tun.example.com -> 127.0.0.1:3000
```

The name is fixed, so the URL you paste into the sender's settings is the same after every restart. Add `--inspect` to let the server keep the headers and the first 64 KiB of every request and response body, so you can look at what the sender really sent and send it again to your service after a fix, without triggering the webhook a second time:

```console
$ porthole http 3000 --name hooks --inspect
```

Inspection is opt-in per tunnel. `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` headers are always stored as `REDACTED`, so a replay does not carry them. Bodies stay in the memory of the server, which can forbid the feature with `traffic.allow_inspect: false` ([details](client.md#expose-a-service)).

The operator reads and replays requests through the admin API with a token that has the scopes `admin:read` and `admin:traffic` ([endpoints](server.md#request-log-and-inspection)):

```console
$ sudo -u porthole portholed token create --name inspector --scopes admin:read,admin:traffic   # on the server
$ curl -H "Authorization: Bearer ph_..." "https://tun.example.com/_porthole/admin/v1/requests?limit=5"
$ curl -X POST -H "Authorization: Bearer ph_..." "https://tun.example.com/_porthole/admin/v1/requests/<id>/replay"
```

or by asking an agent, which has the same operations as the tools `query_requests` and `replay_request` ([agents](agents.md#tools)).

## SSH to a machine at home, by name

On the machine at home (it needs a running sshd):

```console
$ porthole ssh
```

It prints the command for everyone else. On any other machine, with plain OpenSSH and nothing of porthole installed:

```console
$ ssh -J tun.example.com:2222 alice@home
```

Once in `~/.ssh/config` of the machine you connect from, and then `ssh home`, `scp`, `sftp` and `rsync` work with the short name:

```
Host home
    HostName home
    User alice
    ProxyJump tun.example.com:2222
```

On the first connection compare the fingerprint of the gateway's host key with the one `portholed ssh-hostkey` prints on the server. The server needs `ssh_gateway.listen: ":2222"` and that port open. How it works and why the server never sees your password: [SSH by name](ssh.md).

## Private SSH

By default a machine is reachable by anyone who knows its name. With `--private` the gateway first asks for a porthole token:

```console
$ porthole ssh --private
$ ssh -J token@tun.example.com:2222 alice@home       # the password of the jump host is a porthole token
```

The user name `token` selects this mode. Besides the token of `home` itself, a token with the scope `connect:home` works. Make one for a colleague on the server, and revoke it when it is no longer needed:

```console
$ portholed token create --name friend --scopes connect:home
$ portholed token revoke friend
```

You then type two secrets: the token for the gateway and your usual password or key for the machine ([Public and private machines](ssh.md#public-and-private-machines)).

## Postgres or any TCP service on a fixed port

```console
$ porthole tcp 5432 --remote-port 20017
```

The service is now at `tun.example.com:20017`, a port from the server's `tcp_port_range`. Without `--remote-port` the server picks a free port; the port stays reserved for you for 24 hours after the tunnel closes, also across server restarts, so a reconnecting client gets the same address ([reservations](server.md#tcp-ports-and-reservations)). A service on another host of your network works too: `porthole tcp nas.local:5432 --remote-port 20017`.

That port is open to everyone on the internet, so set a strong password and use the service's own TLS. If you only need the database for yourself, do not publish a port: use the SSH tunnel to the machine and forward the port with plain OpenSSH (the machine needs `porthole ssh` running and its sshd must allow forwarding):

```console
$ ssh -J tun.example.com:2222 -L 5432:localhost:5432 alice@home
$ psql -h localhost -p 5432
```

## Several tunnels that survive reboots

List the tunnels in `tunnels.yaml` and let the client daemon keep them up. On a Linux machine with the deb or rpm package of the client:

```console
$ sudo apt install ./porthole_<version>_linux_amd64.deb
$ sudo porthole join --config /etc/porthole/config.yaml https://tun.example.com/j/pj_3kq9w2m1z8xa_...
$ sudo chown porthole-client: /etc/porthole/config.yaml && sudo chmod 0600 /etc/porthole/config.yaml
$ sudoedit /etc/porthole/tunnels.yaml
```

```yaml
version: 1
tunnels:
  blog:
    type: http
    addr: 3000
  db:
    type: tcp
    addr: nas.local:5432
    remote_port: 20017
  ssh:
    type: ssh
```

The entries shipped in the package file are disabled (`enabled: false`); remove that line from the ones you want. Then:

```console
$ sudo systemctl enable --now porthole
$ sudo usermod -aG porthole-client "$USER"        # log in again afterwards
$ porthole status
```

After a change to the file run `porthole reload`: the file is checked first, and a broken one is rejected while the running tunnels stay. Without root, use the [user unit](client.md#linux-as-your-own-user); on macOS and Windows run `porthole daemon` yourself ([details](client.md#run-the-client-as-a-service)). While the daemon runs, `porthole http 3000` adds a tunnel to it for as long as the command runs, and `--detach` keeps it until `porthole close <name>`.

## A Docker service on another machine of your network

The client does not have to run on the machine that hosts the service. Run it on any machine that can reach the service and give `host:port`:

```console
$ porthole http 192.168.1.10:8080 --name wiki
https://wiki-home.tun.example.com -> 192.168.1.10:8080
```

Or run the client in a container next to the service, on the same Docker network. The image reads the server and the token from the environment and reaches the target by its container name:

```console
$ docker run --rm -e PORTHOLE_SERVER=https://tun.example.com -e PORTHOLE_TOKEN=ph_... \
    ghcr.io/eto-a/porthole/porthole:<version> http web:8080
```

`<version>` is the image tag, a release without the leading `v` ([Docker](install.md#docker)).

## "Agent, open a tunnel for me"

An LLM agent can ask a connected machine to open a tunnel, without you logging in to that machine. Three things have to be true: the machine runs the `porthole` daemon, its token allows remote control (the default), and its own `allow_remote` policy accepts the target. Without `allow_remote` in `tunnels.yaml` the machine accepts its own loopback ports and `ssh`, nothing else; a LAN host or another machine's name needs an explicit list (or `allow_remote: any`).

To narrow it further, list in `tunnels.yaml` exactly what may be exposed this way:

```yaml
version: 1
allow_remote: [ssh, 8080]
```

On the server, give the agent a token that can only look and request tunnels, and add the server to Claude Code:

```console
$ sudo -u porthole portholed token create --name ops-agent --scopes admin:read,admin:remote
$ claude mcp add --transport http porthole https://tun.example.com/_porthole/mcp \
    --header "Authorization: Bearer ph_..."
```

Now ask in plain words:

```text
You:    pass me port 8080 from home
Agent:  Port 8080 of "home" is now reachable at https://http-8080-home.tun.example.com
```

Behind the scenes the agent called `list_clients` and `request_tunnel`; a refusal such as `not_allowed` reaches it with its code. The same request without an agent: `portholed admin open home http 8080`. To enrol a new machine the agent uses `create_join_link` and hands you the `porthole join` command. See [agents](agents.md#opening-a-tunnel-on-a-client-from-the-server-side) and [Remote requests](client.md#remote-requests).

## Several machines

One machine, one token, one name. Create a join link per machine; each machine then has its own tunnel namespace (`<tunnel>-<client>`), so `http-8080-home` and `http-8080-office` are different names. Two clients can still compose the same name when their names contain hyphens (client `home` with tunnel `web-a`, client `a-home` with tunnel `web`); the first to register keeps it for good and the second gets `name_taken` (see [Host names](server.md#host-names-are-per-client-tunnel)), so give clients names without hyphens where you can:

```console
$ sudo -u porthole portholed join create --name office
$ sudo -u porthole portholed token list
```

Do not share one token between machines: a second login with the same token replaces the first session (see [Troubleshooting](troubleshooting.md#session_replaced-another-porthole-process-logged-in)). For SSH, list the machines in one `Host` block; without `HostName`, OpenSSH sends the alias as the target name, which is what the gateway expects. A second `ssh` tunnel of one machine, started with `porthole ssh --name nas`, is reached as `nas-home`:

```
Host home office nas-home
    User alice
    ProxyJump tun.example.com:2222
```
