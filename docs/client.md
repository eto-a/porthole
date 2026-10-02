# Client guide (`porthole`)

`porthole` is the client. It opens one outbound TLS connection to your `portholed` server (port 443), so it works from behind NAT and most corporate firewalls, and publishes local services under a public address. Install it first, see [Installation](install.md): `curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh`. You need a join link or a token from the server operator, see [Server setup: Join links](server.md#join-links) and [Tokens](server.md#tokens).

## Join with a link

The easiest way to get credentials: the server operator runs `portholed join create --name <name>` and sends you a one-time link.

```console
$ porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...
joined as home
```

`join` redeems the link, then stores the server and the new token exactly as `login` does (same config file and precedence). The link works once and expires after 15 minutes by default; opening it in a browser only shows this command. With a bare code (`pj_...`) the server comes from `--server`, `$PORTHOLE_SERVER` or the existing config file. `--json` prints `{"joined":true,"client_name":...,"server":...,"config":...}` and never the token. A refused link exits with status 4 (`invalid_code`, `join_code_used`, `join_code_expired`, `join_code_revoked`), a taken name with 5 (`name_taken`), an unreachable server with 3.

A join link decides which server this machine talks to, so use only links from someone you trust. `join` refuses, before it redeems the link (the one-time code is not used up), to replace the server or token of an existing config file without `--force`; the message names the old and the new server. Re-joining the server the config already points to needs no `--force`. A plain `http://` server (anything but localhost or a loopback address) is refused without `--insecure-http`, because the code and the new token would travel unencrypted.

## Log in

```console
$ porthole login https://tun.example.com ph_...           # stores the server and token in your user config
$ porthole login https://tun.example.com ph_... --check   # also connects to the server and verifies the token
```

`login` writes the client config file (mode 0600; default `<user config dir>/porthole/config.yaml`, override with `--config`). The environment variables `PORTHOLE_SERVER` and `PORTHOLE_TOKEN` and the `--server` and `--token` flags of the tunnel commands (with `--no-daemon`) override the stored values. Instead of keeping the token in `config.yaml` you can point `token_file` at a file of its own, see [the system service](#linux-system-wide-deb-and-rpm).

On Unix, porthole refuses a `config.yaml` that holds a `token` and can be read by group or others (`chmod 600`), as it does for a `token_file`. A `token` on the command line (`porthole login <url> <token>`, `--token`) is visible to other users in `ps` and in your shell history; prefer `$PORTHOLE_TOKEN`, a `token_file`, or a join link. A plain `http://` server URL (other than localhost) makes porthole print a warning, and the daemon log one: the token is sent unencrypted. The client never follows an HTTP redirect when it connects to the server.

## Expose a service

```console
$ porthole http 8080                  # https://http-8080-home.tun.example.com
$ porthole http 8080 --name blog      # https://blog-home.tun.example.com
$ porthole http 192.168.1.10:3000     # a host on your network works too
$ porthole tcp 7575                   # tcp://tun.example.com:<port from the range>
$ porthole tcp 192.168.1.5:7575 --remote-port 20017
$ porthole ssh                        # the local sshd, reachable by name through the SSH gateway
```

Here `home` is the client name, the name of the token you logged in with. A bare port means `127.0.0.1:<port>`. Commands run in the foreground, print the public address, and reconnect automatically if the connection drops.

| Command | Public address |
|---|---|
| `porthole http <port\|host:port> [--name] [--inspect]` | `https://<name>-<client>.<domain>`; default name `http-<port>`, so the URL is stable across restarts. HTTP(S) and WebSocket; TLS is terminated on the server |
| `porthole tcp <port\|host:port> [--name] [--remote-port]` | `tcp://<domain>:<port>`, a port from the server's range (`--remote-port` asks for a specific one); default name `tcp-<port>` |
| `porthole ssh [--local-port 22] [--user] [--name] [--private] [--public-port] [--remote-port]` | By default no public port: `ssh -J <gateway> <user>@<client>` through the server's SSH gateway. Default name `ssh`. See [SSH by name](ssh.md) |

`porthole http --inspect` (or `inspect: true` in the tunnels file) asks the server to keep what passes through the tunnel so that you or an agent can look at it later and replay a request:

- Stored: for every request, the headers and the first 64 KiB of the request body and of the response body (with the real size and a `truncated` flag), the response headers and the unmasked request path and query (needed for replay; the logged query has the values of secret-looking parameters such as `token`, `key`, `password`, `secret` and `auth` masked; the full list is in [Request log and inspection](server.md#request-log-and-inspection)). Large responses still reach the visitor in full and stream as usual; only the stored copy is cut. WebSocket and other upgraded connections are never inspected. Bodies are stored as sent, so a compressed response is stored compressed.
- Masked: `Cookie`, `Set-Cookie` and every header whose name looks like a credential (`Authorization`, `Proxy-Authorization`, `X-Api-Key`, ...) are always stored as `REDACTED`; the full rule is in [Request log and inspection](server.md#request-log-and-inspection). A replay therefore reaches your service without them; a service that needs a credential header will answer `401` to a replay. Other headers and bodies are stored as they are, so do not use `--inspect` on a tunnel that carries data you would not want the server operator to read. This was always technically possible for HTTP tunnels (TLS ends at the server); now it is explicit and opt-in per tunnel.
- The data lives in the server's memory only, up to the server's `traffic.max_detail_bytes`, and is lost when the server restarts. A server may forbid inspection (`traffic.allow_inspect: false`); the tunnel is then refused. See [Request log and inspection](server.md#request-log-and-inspection) for how to read it.

`porthole ssh` flags: `--local-port` (default 22) is the port of your sshd, `--user` is the user name in the printed `ssh` command (default: current user), `--private` makes the gateway ask for a porthole token first (and never falls back to a public port), `--public-port` opens a public TCP port of the server instead of using the gateway (`ssh -p <port> <user>@<server>`; `--remote-port` requests that port). If the server has no SSH gateway, a plain `porthole ssh` falls back to a public port with a warning.

If the server cannot be reached at all when the command starts (wrong URL, server down), it gives up after 5 attempts, or at once on an unknown host name or an untrusted certificate; change the limit with `--max-initial-attempts N` (`0` retries forever). Once connected, the command keeps reconnecting. To keep tunnels up across reboots, run the client as a service instead: see [Run the client as a service](#run-the-client-as-a-service).

## Tunnels file

Tunnels that should stay up are listed in a tunnels file, `tunnels.yaml` next to the client config file. It holds no secrets (see [deploy/tunnels.example.yaml](../deploy/tunnels.example.yaml)):

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
    type: ssh             # SSH through the gateway to 127.0.0.1:22 unless addr is given
```

- The key of each entry is the tunnel name: 1 to 32 characters of `a-z`, `0-9` and `-`, not starting or ending with `-`. It becomes part of the public address.
- `type` is `http`, `tcp` or `ssh`; `addr` is `3000`, `:3000` or `host:port`; `enabled: false` disables an entry (the default is `true`).
- `remote_port` is valid for `tcp`, and for `ssh` only together with `public_port: true`.
- `inspect: true` (`http` only) stores request and response bodies on the server, as `porthole http --inspect` does.
- For `type: ssh`, `private: true` makes the SSH gateway ask for a porthole token, and `public_port: true` is the older mode with a public TCP port instead of the gateway.
- An optional top-level `server:` overrides the server of the config file (the token still comes from there).
- On macOS and Windows the file lives in the `porthole` folder of your user configuration directory.

Run the tunnels of the file in the foreground, without a daemon, until interrupted:

```console
$ porthole start                                  # every enabled tunnel
$ porthole start blog db --tunnels ./tunnels.yaml # exactly these tunnels, enabled or not
```

The server is taken from `--server`, `$PORTHOLE_SERVER`, the `server` key of the tunnels file, or the config file, in this order.

### Remote requests

The daemon and `porthole start` accept requests from the server to open a tunnel (an operator runs `portholed admin open`, or an agent calls `request_tunnel`; see the [server guide](server.md#opening-a-tunnel-on-a-clients-machine)). The one-off `porthole http|tcp|ssh` commands never do. The token of the machine must allow remote control, and the machine has the last word: `allow_remote` in the tunnels file lists the local targets that may be exposed this way.

```yaml
version: 1
allow_remote: [ssh, 3000, "192.168.1.5:80"]   # only these local targets
# allow_remote: none                          # refuse every remote request
# allow_remote: any                           # every target (except link-local, see below)
# (no key)                                    # the default: only this machine (loopback, localhost, ssh)
```

- Without the key only services **on this machine** may be exposed: a loopback address (`127.0.0.0/8`, `::1`), `localhost` and `ssh` (`127.0.0.1:22`). Anything else (a LAN host, another machine's name) needs an explicit list or `allow_remote: any`. This protects the network behind the machine from a compromised server or a prompt-injected agent. Before this change a missing key allowed every target.
- An entry is `ssh` (that is `127.0.0.1:22`), a port (`127.0.0.1:<port>`) or `host:port`. A request matches when its target equals an entry exactly (`localhost:3000` is not `127.0.0.1:3000`). With a list, only the listed targets are allowed (loopback is not added implicitly).
- Link-local targets (`169.254.0.0/16`, `fe80::/10`: cloud instance metadata services and the like) are refused even under `any`; only an entry that names the exact address (`"169.254.169.254:80"`) allows one.
- `allow_remote:` with no value (also `null`, `~`, or a key whose list items are all commented out) is a configuration error, not "allow everything": write a list, `none` or `any`, or remove the key.
- Names are resolved when a visitor connects, not when the request is checked. An entry like `nas.local:80` follows whatever the machine's resolver, mDNS or hosts file returns at that moment; prefer IP addresses in the list.
- The server cannot widen the list. A refused request is answered with `not_allowed` and logged by the client.
- `porthole reload` applies a changed `allow_remote` to the running daemon. Tunnels that are already open stay open.
- A remotely opened tunnel is a runtime tunnel: `porthole tunnels` shows it, `porthole close <name>` removes it, a daemon restart forgets it.

## Run the client as a service

`porthole daemon` keeps one session to the server and the tunnels listed in the tunnels file up across reboots and network drops (it reconnects forever), and accepts more tunnels from the CLI over a local unix socket. Design: [ADR 0002](adr/0002-client-daemon-and-tunnels-file.md).

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

The daemon runs as the `porthole-client` user (created by the package; it is not the server's `porthole` user), so that user must be able to read the credentials: the commands above hand `config.yaml` to that user, readable by nobody else. Instead of keeping the token in `config.yaml` you can put it in a file of its own, for example `/etc/porthole/token` (one line, owned by `porthole-client`, mode `0600`; porthole refuses a token file that its group or others can read, like ssh does for private keys), and set `token_file: /etc/porthole/token` in `config.yaml` instead of `token`.

The tunnels file of the package is `/etc/porthole/tunnels.yaml`; a pristine copy of the example is also installed as `/usr/share/porthole/tunnels.example.yaml`. The package creates `/etc/porthole/tunnels.yaml` from it only when the file does not exist, and never overwrites or asks about it on upgrade. The entries of the shipped file are all disabled, so installing the package never publishes anything by accident: set `enabled: true` (or delete the line) for the ones you want.

After editing it run `sudo systemctl reload porthole` or `porthole reload`: the file is validated first, a broken file is rejected and the running tunnels stay as they are. A broken file at start stops the service for good (exit code 78) instead of restarting it in a loop; look at `journalctl -u porthole`.

Members of the group `porthole-client` (and root) can use the daemon's socket, `/run/porthole/porthole.sock`. Adding a tunnel publishes a local service to the Internet, so treat the group like the `docker` group. With the daemon running:

```console
$ porthole http 3000                  # attaches to the daemon; the tunnel closes when you press Ctrl-C
$ porthole http 3000 --detach         # stays until `porthole close http-3000` or a daemon restart
$ porthole close <name>
$ porthole status
```

Tunnels added from the command line are not written to the file: what runs after a reboot is exactly the tunnels file. If a daemon is running but you may not use its socket, `porthole http` fails with a hint instead of starting a second session with the same token (that would replace the daemon's session). `--no-daemon` forces a standalone run, and `--daemon` makes the command fail when no daemon is reachable.

### Linux, as your own user

No root and no extra user: copy [deploy/porthole.user.service](../deploy/porthole.user.service) to `~/.config/systemd/user/porthole.service`, run `porthole login` and create `~/.config/porthole/tunnels.yaml`, then `systemctl --user enable --now porthole` (the header of the unit has the details, including `loginctl enable-linger`). The socket is then `$XDG_RUNTIME_DIR/porthole/porthole.sock`, which only you can reach.

### `porthole service` (Linux, macOS, Windows)

One command group installs and controls the service on every OS (design: [ADR 0006](adr/0006-windows-and-macos-clients.md)). It manages the system-wide service by default, which needs root or Administrator: porthole never elevates itself, so open a terminal that already has the rights (`sudo` on Linux and macOS, "Run as administrator" on Windows). Put the `porthole` binary where it will stay first: the service points at the file you run.

```console
$ sudo porthole login --system https://tun.example.com ph_...     # or: sudo porthole join --system <link>
$ sudo porthole service install                                    # register, enable at boot, start
$ porthole service status                                          # service state plus what the daemon says
$ porthole status                                                  # the same daemon, through its local API
$ porthole http 3000                                               # attaches to the service's daemon
$ sudo porthole service restart                                    # also: start, stop, uninstall
```

On Windows run the same commands without `sudo` in an Administrator terminal. `login --system` writes the config file of the service, `install` checks it and the tunnels file before it changes anything, copies your own config file when the system one does not exist yet, never overwrites an existing `config.yaml` or `tunnels.yaml`, and creates an empty `tunnels.yaml` when there is none (add tunnels to it, then `porthole reload`). Running `install` again updates the definition and restarts the service. `uninstall` leaves the configuration files in place. Every command accepts `--json`; `status` exits with 0 even when the service is not installed, so read `service.installed` and `service.running`.

| | Linux | macOS | Windows |
|---|---|---|---|
| service | systemd unit `porthole.service`, runs as `porthole-client` | LaunchDaemon `io.github.eto-a.porthole`, runs as root | Windows service `porthole`, runs as LocalSystem, starts automatically (delayed) |
| configuration | `/etc/porthole/{config,tunnels}.yaml` | `/Library/Application Support/porthole/{config,tunnels}.yaml` | `%ProgramData%\porthole\{config,tunnels}.yaml` (Administrators and SYSTEM only) |
| log | `journalctl -u porthole` | `/Library/Logs/porthole/` | `%ProgramData%\porthole\logs\porthole.log` (10 MiB, one `.1` copy), start, stop and failure in the Event Log (source `porthole`) |
| local API | `/run/porthole/porthole.sock`, group `porthole-client` | `/var/run/porthole/porthole.sock`, root only (directory 0700) | named pipe `\\.\pipe\ProtectedPrefix\Administrators\porthole` |
| reload | `systemctl reload porthole` or `porthole reload` | `porthole reload` | `porthole reload` or `sc control porthole paramchange` |
| per-user variant | `porthole service install --user` (systemd user unit) | `porthole service install --user` (LaunchAgent) | none, see below |

Who may use the local API of the system service: on Linux the members of the group `porthole-client` (`sudo usermod -aG porthole-client $USER`, then log in again), on macOS only root (run `sudo porthole ...`; the socket directory is 0700), on Windows Administrators and SYSTEM plus the users and groups named with `--allow` at install time, for example `porthole service install --allow BUILTIN\Users` (repeat the flag for more). On Windows an `--allow` principal is an unprivileged peer, the twin of the `porthole-client` group on Linux: it may publish only loopback targets (and what `allow_remote` lists), close only the tunnels it added, and cannot reload. Full control stays with SYSTEM, the account of the service and callers whose token is an elevated Administrator (a UAC-filtered token does not count, so use an elevated terminal); a caller whose identity cannot be read is treated as unprivileged. Adding a tunnel publishes a local service to the Internet, so keep this list short. A user who may not use the endpoint gets a message saying so, not a second session with the same token.

The system service runs with the rights of the system, so `service install` does not register a binary that a user who is not an administrator could replace (the owner or ACL of the file or of a directory above it gives such a user write rights on Windows, and so does a file owned by your own account even if you are an administrator, since your non-elevated programs could change it; on Linux and macOS the file or a parent directory is not owned by root or is writable by group or others, as with a Homebrew install or a file in Downloads). It copies the running binary to `%ProgramData%\porthole\bin\porthole.exe` (Windows), `/Library/Application Support/porthole/bin/porthole` (macOS) or `/usr/local/lib/porthole/porthole` (Linux), registers the copy and says so; run `porthole service install` again after upgrading porthole (on Windows run `porthole service stop` first, a running binary cannot be replaced); `porthole service status` warns when the service runs another version than the command. An explicit `--config` or `--tunnels` file that such a user could edit is refused. `--allow-unsafe-path` registers the running binary as it is and prints a warning. The same applies to `%ProgramData%\porthole` on Windows and to `/Library/Application Support/porthole` and `/Library/Logs/porthole` on macOS: a directory that already exists is accepted only if it and everything inside it belongs to the administrators (root), has no entry for other users and contains no links; otherwise install stops and tells you to inspect and delete it, because any user can create `%ProgramData%\porthole` before the administrator does. The service verifies its directory again before it opens its log file.

`--user` (Linux, macOS) installs a service of your own account: no root, your own config directory and your own socket. Linux needs `loginctl enable-linger $USER` to keep it running after you log out.

#### Windows without a service: Task Scheduler

Windows has no per-user service. To run a daemon of your own at logon, with your own credentials (`porthole login`) and your own pipe (`\\.\pipe\porthole-<your SID>`), register a task from a normal terminal:

```console
> schtasks /Create /TN porthole /SC ONLOGON /RL LIMITED /TR "\"C:\Program Files\porthole\porthole.exe\" daemon"
> schtasks /Run /TN porthole
> schtasks /Delete /TN porthole /F        # to remove it
```

Adjust the path of `porthole.exe` to where you put it. A system service and your own daemon use different pipes, so both can exist at once; `porthole http` looks at your own first.

## Talking to the daemon

| Command | Purpose |
|---|---|
| `porthole daemon [--config] [--tunnels] [--socket] [--allow]` | Run the client daemon: the tunnels file plus tunnels added from the CLI. A broken configuration makes it exit with status 78. `SIGHUP` re-reads the tunnels file |
| `porthole status [--json]` | Show the daemon's connection and tunnels |
| `porthole tunnels` | List the tunnels of the daemon |
| `porthole reload` | Make the daemon re-read the tunnels file and apply the difference: new tunnels are registered, removed ones are closed, changed ones are registered again, the rest is not touched. An invalid file is rejected as a whole |
| `porthole close <name>` | Remove a tunnel added with `--detach`; tunnels of the file are removed by editing the file and running `porthole reload` |
| `porthole http\|tcp\|ssh ... [--detach\|--no-daemon\|--daemon]` | With a running daemon, add the tunnel to it (it is removed when the command ends; `--detach` keeps it until `porthole close` or a daemon restart, and implies `--daemon`); `--no-daemon` runs it in this process, `--daemon` requires the daemon |

The socket is chosen from `--socket`, then `$PORTHOLE_SOCKET`, then the user socket, then the system socket.

## Security notes

- **The socket is the permission.** Whoever can open the daemon's socket may publish tunnels under this machine's identity. The user socket is mode 0600 in your own directory. The system socket belongs to the group `porthole-client`, so adding a user to that group is a grant comparable to the `docker` group, though narrower. On Linux the daemon reads the peer's uid (`SO_PEERCRED`) and, for a caller that is neither root nor the daemon's own user, (1) applies the `allow_remote` policy to the tunnels it adds (loopback only by default), (2) lets it close only the tunnels it added itself, and (3) refuses `reload`. Listing tunnels and the event stream stay open to every caller. On Windows the daemon reads the SID and the token of the pipe client instead: SYSTEM, the account of the service and elevated Administrators are trusted, everybody else that `--allow` admitted gets the same restrictions (and a client whose SID cannot be read is restricted too). On macOS the system socket is root only (directory 0700); the per-user daemon has a 0600 socket.
- **`porthole mcp`** only opens tunnels to services on this machine (loopback, `localhost`); pass `--allow-remote-targets` to allow other hosts (link-local addresses stay refused). `open_tunnel` is annotated as destructive so that MCP hosts ask before calling it; use `--read-only` when the agent reads untrusted content.
- **The tunnels file** can redirect the token: a `server:` key there overrides the one in `config.yaml`, and the token of `config.yaml` is sent to it. Keep it writable only by you (the package installs it as `0640 root:porthole-client`). Porthole does not check its mode.
- **Windows:** the endpoint is a named pipe, not a file: `\.\pipe\porthole-<your SID>` with an owner-only ACL for your own daemon, `\.\pipe\ProtectedPrefix\Administrators\porthole` for the system service (only administrators can create pipes there). `--socket` takes a pipe name on Windows.
- **Unix sockets:** the daemon creates the socket and then sets its mode, so a custom `--socket` in a shared directory leaves a short window in which the socket has the umask's permissions. Keep it in a directory only you (or the service user) can enter, as the shipped units do (`UMask=0077`).
- **Remote opens choose public exposure:** a server-requested ssh tunnel may ask for `private=false` or a fixed remote port; `allow_remote` limits the local target only, not these options.

## Command reference

| Command | Purpose |
|---|---|
| `porthole join <link\|code> [--server] [--force] [--insecure-http] [--system]` | Enrol with a one-time join link and store credentials (`--system` as for `login`) |
| `porthole login <url> <token> [--check] [--system]` | Store credentials (`--system`: in the config file of the system service, needs root or Administrator) |
| `porthole http <port\|host:port> [--name] [--inspect]` | Expose a local web service; `--inspect` stores bodies for the inspector |
| `porthole tcp <port\|host:port> [--name] [--remote-port]` | Expose a local TCP service |
| `porthole ssh [--local-port 22] [--user] [--name] [--private] [--public-port [--remote-port N]]` | Expose the local SSH server |
| `porthole start [names...]` | Run the tunnels of the tunnels file in the foreground, without a daemon |
| `porthole daemon`, `status`, `tunnels`, `reload`, `close <name>` | See [Talking to the daemon](#talking-to-the-daemon) |
| `porthole service install [--user] [--tunnels F] [--allow P] [--allow-unsafe-path]`, `service uninstall\|start\|stop\|restart\|status [--user]` | Install and control the service, see [`porthole service`](#porthole-service-linux-macos-windows) |
| `porthole doctor [--system]` | Read-only diagnosis of this machine: config, DNS, login, daemon, tunnels file, service. See [Troubleshooting](troubleshooting.md#diagnose-a-client-porthole-doctor) |
| `porthole version` | Print the version |

Global flags: `--config` (default `<user config dir>/porthole/config.yaml`), `--socket`, `-v, --verbose`, `--json`. Run `porthole <command> --help` for everything.

### Machine-readable output (`--json`)

With `--json`, stdout carries only JSON; messages for people go to stderr or are left out. A command that ends by itself (`login`, `status`, `tunnels`, `reload`, `close`, `version`, `http|tcp|ssh --detach`) writes one JSON document. A command that keeps running (`http`, `tcp`, `ssh`, `start`) writes [JSON Lines](https://jsonlines.org/): one compact object per line, each with an `event` member:

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

`porthole http 8080 --detach --json` prints the tunnel object (the same as one element of `porthole tunnels --json`). `porthole login --json` prints `{"saved":true,"server":...,"config":...}` plus a `check` object with `--check`; it never prints the token. `porthole daemon --json` writes its log to stderr as JSON and nothing to stdout.

A failure writes `{"error":{"code":"...","message":"..."}}` to stdout and exits with a non-zero status (without `--json` the message goes to stderr as `porthole: <message>`). `code` is the server's error code where there is one (`unauthorized`, `token_revoked`, `token_expired`, `name_taken`, `forbidden`, `limit_exceeded`, `port_unavailable`, ...), otherwise one of `usage`, `connect_failed`, `auth_failed`, `tunnel_rejected`, `daemon_unavailable`, `permission_denied`, `config` or `error`. `porthole reload --json` prints its result document even when some tunnels failed (they are in `errors`) and then exits with status 5, without a second document.

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

A token that the server rejects while `porthole daemon` or the system service runs also exits with 78, so that the service does not retry forever; the foreground commands report it as 4.

## Docker (sidecar)

The client image reads `PORTHOLE_SERVER` and `PORTHOLE_TOKEN` from the environment, see [Installation: Docker](install.md#docker).
