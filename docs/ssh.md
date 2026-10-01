# SSH by name

The original use case of porthole: reach a machine behind NAT through your own server with plain OpenSSH, by a name you can remember, with nothing of porthole installed on the machine you connect from.

```console
$ ssh -J tun.example.com:2222 alice@home
```

`home` is the client name of the machine. The design and the alternatives that were rejected are in [ADR 0003](adr/0003-ssh-gateway-and-port-reservations.md).

## What you need

- On the server: the SSH gateway enabled with `ssh_gateway.listen` (for example `:2222`) and that port open in the firewall, see [Server setup: SSH gateway](server.md#ssh-gateway).
- On the target machine (the one behind NAT): an SSH server (sshd), `porthole` installed and logged in, see the [Client guide](client.md), and `porthole ssh` running (or a tunnel of `type: ssh` in the [tunnels file](client.md#tunnels-file), kept up by the [daemon](client.md#run-the-client-as-a-service)).
- On the machine you connect from: stock OpenSSH with `ProxyJump` (`ssh -J`, OpenSSH 7.3 or newer). Nothing else.

## Quick start

On the target machine:

```console
$ porthole ssh
```

It prints the command to reach the machine, of the form `ssh -J tun.example.com:2222 <user>@home` (`--user` sets the user name in the printed command; the default is the current user). On any other machine:

```console
$ ssh -J tun.example.com:2222 alice@home
```

You first see the host key of the gateway (compare the fingerprint, see [below](#the-gateways-host-key)), then the login prompt of the target's own sshd: its password, or your key, as usual.

## How it works

`ssh -J` (ProxyJump) connects to the jump host, here the gateway, and asks it to open a `direct-tcpip` channel (RFC 4254 section 7.2) to the target name. The second SSH session, to the target, runs inside that channel. Therefore:

- The gateway forwards ciphertext only. Authentication to the target is the target's own sshd, end to end; the server never sees your password, your key or the session.
- The gateway is not a shell. It accepts only `direct-tcpip` channels and refuses sessions, `exec`, remote port forwarding, agent and X11 forwarding. You cannot log in to the server through it.
- The server routes the channel over the target machine's existing outbound connection, as one more data stream, to its `ssh` tunnel. The requested port is ignored: the tunnel decides the local address (`127.0.0.1:22` unless you set another with `--local-port`).
- No public TCP port is opened for the machine. The only extra port on the server is the gateway port.

```
 you (OpenSSH)                 portholed                      target machine
 ssh -J gw:2222 alice@home --> SSH gateway :2222  --stream-->  porthole --> sshd :22
        \________ inner SSH session, end to end __________________________/
```

## Names

The name after `@` selects the tunnel:

| You connect to | Meaning |
|---|---|
| `home` | The `ssh` tunnel of the client `home` |
| `nas-home` | The tunnel `nas` (of type `ssh`) of the client `home`: `<tunnel>-<client>` |
| `home.tun.example.com` | The same as `home`; a trailing `.<domain>` is accepted and stripped |

An unknown or not allowed target gets the same reply, so the gateway does not reveal which machines exist.

## Public and private machines

By default a machine is **public**: the gateway accepts the SSH `none` method, so you see only the target's own password or key prompt. Exposure is comparable to a public TCP port, but a scanner must know a valid name.

With `porthole ssh --private` (or `private: true` in the tunnels file) the gateway first asks for a porthole token as the password of the jump host. You select this mode with the user name `token`:

```console
$ ssh -J token@tun.example.com:2222 alice@home
```

The password is a porthole token of the same client (the `home` token), or any token with the scope `connect:home` (see [Server setup: Tokens](server.md#tokens): create one for a colleague with `portholed token create --name friend --scopes connect:home`). The token is checked against the server's store on every attempt, so revoking it takes effect at once. Afterwards you enter the target's own password or use your key as usual, so you type two secrets. `--private` never falls back to a public port.

## `~/.ssh/config`

Once in the config of the machine you connect from:

```
Host home
    HostName home
    User alice
    ProxyJump tun.example.com:2222
```

Then `ssh home`, and also `scp`, `sftp` and `rsync` over it, work with the short name. For a private machine use `ProxyJump token@tun.example.com:2222`.

## Several machines and sessions

- **Several machines.** Give each machine its own token (`portholed token create --name home`, `--name office`, ...); the token name is the machine name. Several `ssh` tunnels of one client are named by `porthole ssh --name nas` (reached as `nas-home`), or by several `type: ssh` entries in the tunnels file.

  ```
  Host home office nas-home
      User alice
      ProxyJump tun.example.com:2222
  ```

  Without `HostName`, OpenSSH sends the alias itself as the target name, which is what the gateway expects.
- **Parallel sessions.** Each SSH channel becomes one data stream over the machine's single connection to the server, so any number of sessions, users and target machines work at once, up to `ssh_gateway.max_conns_per_tunnel` concurrent channels per tunnel (default 256).
- **Idle connections.** The gateway closes connections that have no channels after 60 seconds, and gives a client 10 seconds to complete the handshake.

## The gateway's host key

The first time you connect, OpenSSH shows the host key fingerprint of the jump host and asks you to confirm it. Compare it with the one the server operator gives you: the server logs it at the first start, and `portholed ssh-hostkey` prints it again:

```console
$ portholed ssh-hostkey
```

The key is an ed25519 key stored as `ssh_host_ed25519_key` in the server's data directory. After the first confirmation OpenSSH remembers it in `~/.ssh/known_hosts` (for a non-default port under `[tun.example.com]:2222`). The target machine has a host key of its own, shown on the first connection to it.

## The older mode: a public port

`porthole ssh --public-port` (or `public_port: true` for a `type: ssh` tunnel) skips the gateway and opens a public TCP port of the server instead, `ssh -p <port> alice@tun.example.com`; `--remote-port` requests a specific port. The port comes from the server's `tcp_port_range` and is [reserved](server.md#tcp-ports-and-reservations) for the machine for 24 hours after the tunnel closes. It is also the automatic fallback of a plain `porthole ssh` when the server has no SSH gateway (with a warning). The port is open to everyone on the internet; prefer the gateway.
