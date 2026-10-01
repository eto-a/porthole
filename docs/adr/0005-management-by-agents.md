# 0005. Management by LLM agents: admin API, MCP, traffic analysis

- Status: accepted
- Date: 2026-10-01
- Issues: #8 (admin API), #9 (MCP), #10 (--json), #11 (audit), #12 (join links), #17 (metrics); new issues for the
  request log and inspector, and for remote tunnel requests

## Context

DESIGN §3.11 makes LLM agents (Claude Code or any MCP client) the management interface instead of a web UI. This ADR
fixes the details agreed with the user: where agents connect, how secrets stay out of model context, and what an agent
may observe about traffic.

## Decision

### Two MCP surfaces

- **A — operator agent, on the server.** `portholed` serves MCP over Streamable HTTP at
  `https://<domain>/_porthole/mcp`, authenticated with a bearer admin token, so a laptop adds it with one
  `claude mcp add --transport http ...` (no local runtime, unlike npx-based servers). `portholed mcp` (stdio) offers
  the same tools on the server itself. Both are thin layers over the **admin API**, which is the only management
  surface; `portholed token ...` moves onto it.
- **B — agent on a client machine.** `porthole mcp` (stdio) talks to the local daemon over its unix socket; access to
  the socket is the permission (ADR 0002), no token in the agent's hands.
- SDK: `github.com/modelcontextprotocol/go-sdk` (used by github-mcp-server). Tools are grouped into toolsets;
  `--read-only` disables every mutating tool and wins over scopes (github-mcp-server `--read-only`).

### Least privilege and secrets

- Each agent gets its own token with narrow scopes: `admin:read`, `admin:tunnels`, `admin:clients`, `admin:tokens`,
  `admin:remote` (open tunnels on machines), `admin:traffic` (request details and bodies).
- **No long-lived secret ever reaches an agent.** Instead of returning a token, `create_join_link` returns
  `porthole join https://<domain>/j/<code>`: single use, expires in 15 minutes by default, bound to a client name and
  scopes chosen at creation. The machine redeems it and receives its permanent token directly; the server stores only
  a hash of the code. Join codes are listed and revocable like tokens.
- Every mutating admin call is written to an append-only audit log (time, acting token id, tool, arguments without
  secrets, result).

### Remote tunnel requests

- The user's request "open me a new tunnel from home" must work end to end: an operator agent calls `request_tunnel`
  (client, kind, local address, options), the server forwards it over the client's live session, and the client
  opens the tunnel and reports its public address.
- Permission is per machine and given once: a machine enrolled through a join link created with remote control
  enabled (the default for links an agent creates) accepts remote requests for any local address. The machine can
  narrow or refuse this in its own `tunnels.yaml` (`allow_remote: [ssh, 3000]`, or `allow_remote: none`); the client
  enforces its list and the server cannot widen it.
  *Amended: default narrowed to the machine's own loopback after the security review.* Without `allow_remote` a
  machine now accepts only loopback targets (`127.0.0.1`, `::1`, `localhost`) and `ssh`; `allow_remote: any` allows
  every target except link-local addresses.
- Requires the `admin:remote` scope; every remote request is audited with the acting token. Remotely opened tunnels
  are runtime tunnels of the daemon (ADR 0002): they survive reconnects, not a daemon restart, and are listed and
  closed like any other.

### Observability and traffic analysis

- The server terminates TLS for HTTP tunnels, so it records every proxied request in a **request log**: time, tunnel,
  visitor IP, method, host, path, status, latency, bytes in/out, user agent. Always on.
- **Inspection** (`--inspect` on a tunnel, `inspect: true` in `tunnels.yaml`): request and response bodies up to
  64 KiB each, plus replay of a recorded request (ngrok inspector). Off by default: bodies carry credentials and
  personal data.
- `Authorization`, `Cookie`, `Set-Cookie` and `Proxy-Authorization` are always redacted in stored headers.
- TCP tunnels and the SSH gateway record connection metadata only (visitor IP, start, duration, bytes, outcome);
  gateway authentication failures are logged per IP. SSH payloads are end-to-end encrypted and never visible.
- Storage: an in-memory ring buffer (default 10 000 requests and 10 000 connections, configurable), lost on restart.
  Prometheus metrics on a localhost listener for external monitoring (#17 moves to v0.3).

### Tools

- A: `server_status`, `list_clients`, `disconnect_client`, `list_tunnels`, `close_tunnel`, `request_tunnel`,
  `create_join_link`, `list_tokens`, `revoke_token`, `query_requests` (filters and aggregates: top paths, status
  classes, visitors, latency percentiles), `get_request`, `replay_request`, `connection_log`,
  `gateway_auth_failures`, `audit_log`, `get_metrics`.
- B: `open_tunnel`, `close_tunnel`, `list_tunnels`, `status`, `query_requests` (own tunnels only).
- Every CLI command gains `--json` and documented exit codes (#10), so agents without MCP can use a shell.

## Consequences

- One management path (admin API) with three thin clients: CLI, MCP over HTTP, MCP over stdio.
- Agents can investigate problems ("why does blog-home return 502", "who scans /wp-admin") without shell access to
  the server.
- Request logging adds per-request work and memory on the server; it is bounded by the ring buffer size.
- Inspection makes the server operator able to read tunnel traffic; this was always technically true for HTTP tunnels
  (TLS terminates at the server) and is now explicit and opt-in per tunnel.
