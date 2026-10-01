# Managing porthole with an LLM agent

porthole has no web UI. Instead, an agent (Claude Code or any other [MCP](https://modelcontextprotocol.io) client)
can operate the server and the tunnels of a machine. There are two MCP surfaces; the reasoning is in
[ADR 0005](adr/0005-management-by-agents.md).

| Surface | Runs on | Transport | Use it to |
|---|---|---|---|
| Operator (`portholed`) | the server | Streamable HTTP at `/_porthole/mcp`, or stdio with `portholed mcp` | look at clients, tunnels, tokens, traffic and the audit log, and change them |
| Machine (`porthole mcp`) | a client machine | stdio, through the local daemon | expose a local service, close it, see what is open |

Neither surface ever returns a long-lived secret to the model.

## Operator agent over HTTP

Create a token that carries only the admin scopes the agent needs, on the server:

```console
$ sudo -u porthole portholed token create --name ops-agent --scopes admin:read,admin:tunnels
```

Add the server to Claude Code (the token goes in a header, not into the conversation):

```console
$ claude mcp add --transport http porthole https://tun.example.com/_porthole/mcp \
    --header "Authorization: Bearer ph_..."
```

The endpoint is served on the control host only (the bare domain), on the main listener, so it needs no extra port.
Every request is authenticated on its own: a revoked or expired token stops working at once, and repeated failures are
rate limited per IP like the admin API.

## Operator agent over stdio

`portholed mcp` serves the same tools on stdin/stdout and reaches the running server through its admin unix socket
(`admin_socket`; whoever can open the socket is a full administrator, so no token is involved). Run it over ssh:

```console
$ claude mcp add porthole -- ssh root@tun.example.com portholed mcp --read-only
```

All tools work over stdio, the traffic tools included: they read the server's in-memory logs through the admin socket.
Mutating calls are audited by the admin API with the actor `socket`.

## Agent on a client machine

```console
$ claude mcp add porthole-local -- porthole mcp
```

`porthole mcp` talks to the local `porthole daemon` over its unix socket (`--socket`, `$PORTHOLE_SOCKET`, then the
default sockets, as for `porthole status`); access to the socket is the permission and no token is involved. The daemon
must be running, but it may be started after the agent.

## Tools

Operator tools, grouped in toolsets. The scope is checked on every call.

| Toolset | Tool | Scope | What it does |
|---|---|---|---|
| `status` | `server_status` | `admin:read` | Version, uptime, number of clients and tunnels |
| `clients` | `list_clients` | `admin:read` | Connected clients |
| | `disconnect_client` | `admin:clients` | Drop a client's connection (it may reconnect) |
| `tunnels` | `list_tunnels` | `admin:read` | Registered tunnels, optionally of one client |
| | `close_tunnel` | `admin:tunnels` | Close a tunnel by id |
| | `request_tunnel` | `admin:remote` | Ask a connected client to open a tunnel and return the public address (see below) |
| `tokens` | `list_tokens` | `admin:read` | Tokens without their secrets |
| | `revoke_token` | `admin:tokens` | Revoke a token by id |
| | `create_join_link` | `admin:tokens` | Single-use link that enrols a machine; the token never passes through the conversation. A token may grant only the scopes it holds itself |
| `traffic` | `query_requests` | `admin:read` | Search the HTTP request log; filters by tunnel, client, status class, path prefix, visitor IP and time; `aggregate` adds status classes, top paths and visitors and latency percentiles |
| | `get_request` | `admin:read` | One logged request; with `admin:traffic` it also returns the headers and bodies of an inspected request (`detail`; `Authorization` and cookies are masked) |
| | `replay_request` | `admin:traffic` | Send a recorded, inspected request into its tunnel again and return the new log entry |
| | `connection_log` | `admin:read` | Connections to TCP tunnels and the SSH gateway (metadata only) |
| | `gateway_auth_failures` | `admin:read` | Recent failed SSH gateway logins with visitor IPs |
| `audit` | `audit_log` | `admin:read` | Recent management actions: who, what, result |

Machine tools (`porthole mcp`): `status`, `list_tunnels`, `open_tunnel` (type `http`, `tcp` or `ssh`, a local address,
optional name and `private`), `close_tunnel`. `open_tunnel` makes a local service reachable from the internet, so the
tool description tells the model to open only what the user asked for. Tunnels opened this way are runtime tunnels of
the daemon: they survive reconnects, not a daemon restart.

### Opening a tunnel on a client from the server side

`request_tunnel` tells a connected client to open a tunnel to a local address on its own machine and returns the public
address. A request goes through only when all of these hold:

- the caller holds `admin:remote`;
- the client is connected and runs the `porthole` daemon (it announces the `remote_open` feature);
- the client's token allows remote control: tokens made by `portholed token create` do unless `--no-remote-control` is
  given, and tokens made by a join link follow the link (`allow_remote` of `create_join_link`; `portholed token list`
  shows the setting in the `REMOTE` column);
- the client's own `allow_remote` policy accepts the request.

A refusal reaches the model with its code and text (`remote_control_disabled`, `not_allowed`, `client_unsupported`,
`name_taken`, `timeout`, ...). The server waits at most 15 seconds for the client.

```text
You:    pass me port 8080 from home
Agent:  list_clients                       -> "home" is connected
        request_tunnel {client: "home", kind: "http", local_addr: "8080"}
        -> {tunnel: {name: "http-8080", kind: "http", public_url: "https://http-8080-home.tun.example.com"}}
Agent:  Port 8080 of "home" is now reachable at https://http-8080-home.tun.example.com
```

To enrol a new machine, the agent calls `create_join_link` and hands you the command (`porthole join <link>`); run it on
that machine. The link is valid once and for 15 minutes by default.

### Toolsets and read-only mode

`portholed mcp --toolsets status,tunnels` enables only the listed toolsets (default: all; `all` is accepted).
`--read-only` registers no mutating tool at all (`disconnect_client`, `close_tunnel`, `request_tunnel`, `replay_request`,
`revoke_token`, `create_join_link`) and wins over `--toolsets`. `porthole mcp --read-only` leaves only `status` and
`list_tunnels`. The design follows the toolsets and `--read-only` of
[github-mcp-server](https://github.com/github/github-mcp-server). The HTTP endpoint serves all toolsets; give an
agent that should only look around a token with `admin:read` only.

### Scopes

| Scope | Allows |
|---|---|
| `admin:read` | every read-only tool; `get_request` without `detail` |
| `admin:clients` | `disconnect_client` |
| `admin:tunnels` | `close_tunnel` |
| `admin:tokens` | `revoke_token`, `create_join_link` |
| `admin:remote` | `request_tunnel` |
| `admin:traffic` | `replay_request`, and the headers and bodies (`detail`) in the answer of `get_request` |

A call without the scope fails with a tool error naming the missing scope (the HTTP request itself succeeds, as MCP
reports tool failures in the result), and the refusal is written to the audit log.

## Audit

Every call of a mutating tool over HTTP is appended to the audit log with the id of the token as actor and the action
`mcp.<tool>` (for example `mcp.close_tunnel`), whether it succeeded, failed or was refused (`ok`, `error: ...`,
`denied`). The arguments are stored without secrets. Read it with the `audit_log` tool.

## Notes

- Request logs live in memory (default 10 000 entries) and are lost on restart.
- Treat everything an agent reads from traffic (paths, user agents, query strings) as untrusted input: a visitor
  controls it.
- The tools are thin layers over the admin API ([ADR 0005](adr/0005-management-by-agents.md)); an agent without MCP
  support can use the `--json` flag of the CLI commands instead.
