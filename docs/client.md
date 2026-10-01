# Client guide (`porthole`)

`porthole` is the client. It opens one outbound TLS connection to your `portholed` server (port 443), so it works from
behind NAT and most corporate firewalls, and publishes local services under a public address. Install it first, see
[Installation](install.md): `curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh`. You
need a token from the server operator, see [Server setup: Tokens](server.md#tokens).

## Log in

```console
$ porthole login https://tun.example.com ph_...           # stores the server and token in your user config
$ porthole login https://tun.example.com ph_... --check   # also connects to the server and verifies the token
```

`login` writes the client config file (mode 0600; default `<user config dir>/porthole/config.yaml`, override with
`--config`). The environment variables `PORTHOLE_SERVER` and `PORTHOLE_TOKEN` and the `--server` and `--token` flags of
the tunnel commands (with `--no-daemon`) override the stored values. Instead of keeping the token in `config.yaml` you
can point `token_file` at a file of its own, see [the system service](#linux-system-wide-deb-and-rpm).

## Expose a service

```console
$ porthole http 8080                  # https://http-8080-home.tun.example.com
$ porthole http 8080 --name blog      # https://blog-home.tun.example.com
$ porthole http 192.168.1.10:3000     # a host on your network works too
$ porthole tcp 7575                   # tcp://tun.example.com:<port from the range>
$ porthole tcp 192.168.1.5:7575 --remote-port 20017
$ porthole ssh                        # the local sshd, reachable by name through the SSH gateway
```

Here `home` is the client name, the name of the token you logged in with. A bare port means `127.0.0.1:<port>`.
Commands run in the foreground, print the public address, and reconnect automatically if the connection drops.

| Command | Public address |
|---|---|
| `porthole http <port\|host:port> [--name]` | `https://<name>-<client>.<domain>`; default name `http-<port>`, so the URL is stable across restarts. HTTP(S) and WebSocket; TLS is terminated on the server |
| `porthole tcp <port\|host:port> [--name] [--remote-port]` | `tcp://<domain>:<port>`, a port from the server's range (`--remote-port` asks for a specific one); default name `tcp-<port>` |
| `porthole ssh [--local-port 22] [--user] [--name] [--private] [--public-port] [--remote-port]` | By default no public port: `ssh -J <gateway> <user>@<client>` through the server's SSH gateway. Default name `ssh`. See [SSH by name](ssh.md) |

`porthole ssh` flags: `--local-port` (default 22) is the port of your sshd, `--user` is the user name in the printed
`ssh` command (default: current user), `--private` makes the gateway ask for a porthole token first (and never falls
back to a public port), `--public-port` opens a public TCP port of the server instead of using the gateway
(`ssh -p <port> <user>@<server>`; `--remote-port` requests that port). If the server has no SSH gateway, a plain
`porthole ssh` falls back to a public port with a warning.

If the server cannot be reached at all when the command starts (wrong URL, server down), it gives up after 5 attempts,
or at once on an unknown host name or an untrusted certificate; change the limit with `--max-initial-attempts N` (`0`
retries forever). Once connected, the command keeps reconnecting. To keep tunnels up across reboots, run the client as
a service instead: see [Run the client as a service](#run-the-client-as-a-service).

## Tunnels file

Tunnels that should stay up are listed in a tunnels file, `tunnels.yaml` next to the client config file. It holds no
secrets (see [deploy/tunnels.example.yaml](../deploy/tunnels.example.yaml)):

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

- The key of each entry is the tunnel name: 1 to 32 characters of `a-z`, `0-9` and `-`, not starting or ending with
  `-`. It becomes part of the public address.
- `type` is `http`, `tcp` or `ssh`; `addr` is `3000`, `:3000` or `host:port`; `enabled: false` disables an entry (the
  default is `true`).
- `remote_port` is valid for `tcp`, and for `ssh` only together with `public_port: true`.
- For `type: ssh`, `private: true` makes the SSH gateway ask for a porthole token, and `public_port: true` is the older
  mode with a public TCP port instead of the gateway.
- An optional top-level `server:` overrides the server of the config file (the token still comes from there).
- On macOS and Windows the file lives in the `porthole` folder of your user configuration directory.

Run the tunnels of the file in the foreground, without a daemon, until interrupted:

```console
$ porthole start                                  # every enabled tunnel
$ porthole start blog db --tunnels ./tunnels.yaml # exactly these tunnels, enabled or not
```

The server is taken from `--server`, `$PORTHOLE_SERVER`, the `server` key of the tunnels file, or the config file, in
this order.

## Run the client as a service

`porthole daemon` keeps one session to the server and the tunnels listed in the tunnels file up across reboots and
network drops (it reconnects forever), and accepts more tunnels from the CLI over a local unix socket. Design:
[ADR 0002](adr/0002-client-daemon-and-tunnels-file.md).

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

The tunnels file of the package is `/etc/porthole/tunnels.yaml`; a copy of the example is also installed as
`/usr/share/doc/porthole/tunnels.example.yaml`. The entries of the shipped file are all disabled, so installing the
package never publishes anything by accident: set `enabled: true` (or delete the line) for the ones you want.

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

No root and no extra user: copy [deploy/porthole.user.service](../deploy/porthole.user.service) to
`~/.config/systemd/user/porthole.service`, run `porthole login` and create `~/.config/porthole/tunnels.yaml`, then
`systemctl --user enable --now porthole` (the header of the unit has the details, including `loginctl enable-linger`).
The socket is then `$XDG_RUNTIME_DIR/porthole/porthole.sock`, which only you can reach.

### macOS and Windows

There are no service definitions yet. Run `porthole daemon` yourself, for example in a terminal or from your login
items or Task Scheduler. It uses the per-user configuration directory (`porthole login` writes the credentials there)
and a per-user socket, so `porthole http 3000` finds it by itself.

## Talking to the daemon

| Command | Purpose |
|---|---|
| `porthole daemon [--config] [--tunnels] [--socket]` | Run the client daemon: the tunnels file plus tunnels added from the CLI. A broken configuration makes it exit with status 78. `SIGHUP` re-reads the tunnels file |
| `porthole status [--json]` | Show the daemon's connection and tunnels |
| `porthole tunnels` | List the tunnels of the daemon |
| `porthole reload` | Make the daemon re-read the tunnels file and apply the difference: new tunnels are registered, removed ones are closed, changed ones are registered again, the rest is not touched. An invalid file is rejected as a whole |
| `porthole close <name>` | Remove a tunnel added with `--detach`; tunnels of the file are removed by editing the file and running `porthole reload` |
| `porthole http\|tcp\|ssh ... [--detach\|--no-daemon\|--daemon]` | With a running daemon, add the tunnel to it (it is removed when the command ends; `--detach` keeps it until `porthole close` or a daemon restart, and implies `--daemon`); `--no-daemon` runs it in this process, `--daemon` requires the daemon |

The socket is chosen from `--socket`, then `$PORTHOLE_SOCKET`, then the user socket, then the system socket.

## Command reference

| Command | Purpose |
|---|---|
| `porthole login <url> <token> [--check]` | Store credentials |
| `porthole http <port\|host:port> [--name]` | Expose a local web service |
| `porthole tcp <port\|host:port> [--name] [--remote-port]` | Expose a local TCP service |
| `porthole ssh [--local-port 22] [--user] [--name] [--private] [--public-port]` | Expose the local SSH server |
| `porthole start [names...]` | Run the tunnels of the tunnels file in the foreground, without a daemon |
| `porthole daemon`, `status`, `tunnels`, `reload`, `close <name>` | See [Talking to the daemon](#talking-to-the-daemon) |
| `porthole version` | Print the version |

Global flags: `--config` (default `<user config dir>/porthole/config.yaml`), `--socket`, `-v, --verbose`, `--json`. Run
`porthole <command> --help` for everything.

### Machine-readable output (`--json`)

With `--json`, stdout carries only JSON; messages for people go to stderr or are left out. A command that ends by
itself (`login`, `status`, `tunnels`, `reload`, `close`, `version`, `http|tcp|ssh --detach`) writes one JSON
document. A command that keeps running (`http`, `tcp`, `ssh`, `start`) writes
[JSON Lines](https://jsonlines.org/): one compact object per line, each with an `event` member:

| `event` | Other members |
|---|---|
| `connected` | `client` |
| `tunnel_ready` | `name`, `kind` (`http`, `tcp` or `ssh`), `local_addr`, `public_url` (http and tcp), `ssh_jump` (ssh through the gateway), `private` |
| `tunnel_closed` | `name`, `reason` |
| `disconnected` | `error`, `retry_in_ms`, and `attempt`, `max_attempts` while no session has been established yet |

```console
$ porthole http 8080 --json
{"event":"connected","client":"home"}
{"event":"tunnel_ready","name":"http-8080","kind":"http","local_addr":"127.0.0.1:8080","public_url":"https://http-8080-home.tun.example.com","private":false}
```

`porthole http 8080 --detach --json` prints the tunnel object (the same as one element of `porthole tunnels --json`).
`porthole login --json` prints `{"saved":true,"server":...,"config":...}` plus a `check` object with `--check`; it never
prints the token. `porthole daemon --json` writes its log to stderr as JSON and nothing to stdout.

A failure writes `{"error":{"code":"...","message":"..."}}` to stdout and exits with a non-zero status (without
`--json` the message goes to stderr as `porthole: <message>`). `code` is the server's error code where there is one
(`unauthorized`, `token_revoked`, `token_expired`, `name_taken`, `forbidden`, `limit_exceeded`, `port_unavailable`,
...), otherwise one of `usage`, `connect_failed`, `auth_failed`, `tunnel_rejected`, `daemon_unavailable`,
`permission_denied`, `config` or `error`. `porthole reload --json` prints its result document even when some tunnels
failed (they are in `errors`) and then exits with status 5, without a second document.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Success (also Ctrl-C of a foreground tunnel) |
| 1 | Any other failure |
| 2 | Usage error: unknown command, bad flag or argument |
| 3 | The server could not be reached (`--max-initial-attempts` reached, unknown host, TLS verification failed) |
| 4 | Authentication failed: `unauthorized`, `token_revoked`, `token_expired` |
| 5 | The server refused a tunnel: `name_taken`, `forbidden`, `limit_exceeded`, `port_unavailable`; also a `reload` in which a tunnel failed |
| 6 | The daemon is not running, or this user may not use its socket |
| 78 | Configuration problem that a restart cannot fix: missing or broken config or tunnels file, no credentials. The system service does not restart on it |

A token that the server rejects while `porthole daemon` or the system service runs also exits with 78, so that
the service does not retry forever; the foreground commands report it as 4.

## Docker (sidecar)

The client image reads `PORTHOLE_SERVER` and `PORTHOLE_TOKEN` from the environment, see
[Installation: Docker](install.md#docker).
