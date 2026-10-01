# porthole wire protocol

Protocol version: **1** · Status: v0.1

This document is normative. `internal/proto` implements it; changes require bumping `protocol_version` or adding
optional fields only.

## 1. Session establishment

1. The client opens a WebSocket connection to `wss://<domain>/_porthole/v1/connect` (plain `ws://` only when the
   server runs in insecure dev mode). WebSocket subprotocol: `porthole.v1`. Binary messages only.
2. The WebSocket byte stream is wrapped as a `net.Conn` and a yamux session is created on top of it.
   The **client** is the yamux client, the **server** is the yamux server.
3. The client opens the first stream: the **control stream**. The server treats the first accepted stream as the
   control stream; any further client-opened stream is a protocol error and closes the session.
4. Handshake on the control stream (deadline 10 s from WebSocket accept):

```
client → server   hello
server → client   hello_ok | error
```

After `hello_ok` both sides read the control stream continuously until the session ends.

## 2. Framing (control stream and stream headers)

```
+----------------------+---------------------------+
| length: uint32 (BE)  | payload: UTF-8 JSON object |
+----------------------+---------------------------+
```

- `length` is the payload length in bytes, 1 ≤ length ≤ 65536. Anything else is a fatal protocol error.
- The payload is a JSON object with a string field `type`. Unknown `type` values are ignored with a log entry
  (forward compatibility); unknown fields inside a known type are ignored.
- Receivers must not allocate more than `length` bytes and must apply a read deadline where stated.

## 3. Messages

All field names are snake_case. Optional fields may be omitted.

### 3.1 Handshake

`hello` (client → server)

| field | type | notes |
|---|---|---|
| `protocol_version` | int | required, currently 1 |
| `token` | string | required, `ph_<id>_<secret>` |
| `client_version` | string | e.g. `0.1.0` |
| `os` | string | `GOOS/GOARCH` |
| `features` | []string | optional capabilities; `remote_open` (see 3.2.1); unknown values are ignored |

`hello_ok` (server → client)

| field | type | notes |
|---|---|---|
| `session_id` | string | random, for logs |
| `client_name` | string | the token's name |
| `server_version` | string | |
| `heartbeat_interval_ms` | int | ping interval the server uses |

### 3.2 Tunnels

`register` (client → server)

| field | type | notes |
|---|---|---|
| `req_id` | int | client-chosen, echoed in the reply |
| `kind` | string | `http` \| `tcp` \| `ssh` (`udp` reserved for v0.2). `ssh` has no public listener: it is reachable only through the server's SSH gateway (ADR 0003). It needs the scope `tunnel:tcp`, and the server answers `invalid_request` when the gateway is disabled (`ssh_gateway.listen` empty) or does not know the kind (older servers) |
| `name` | string | optional; `[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?`. Default `http-<n>` / `tcp-<n>` (chosen by the server or the client CLI), `ssh` for kind `ssh` |
| `remote_port` | int | optional, tcp only: requested public port; must be inside the allowed range |
| `private` | bool | optional, `ssh` only (`invalid_request` for other kinds): the gateway must require a porthole token before it opens the tunnel |
| `inspect` | bool | optional, `http` only (`invalid_request` for other kinds): the server stores request and response headers and the first 64 KiB of each body for the inspector and replay (ADR 0005). `forbidden` if the server sets `traffic.allow_inspect: false`. A server that predates the field ignores it and stores nothing |

`registered` (server → client)

| field | type | notes |
|---|---|---|
| `req_id` | int | |
| `tunnel_id` | string | server-assigned, opaque |
| `kind` | string | |
| `name` | string | effective name |
| `public_url` | string | `https://blog-home.tun.example.com` or `tcp://tun.example.com:20017`; empty for kind `ssh` |
| `private` | bool | optional; echoes `register.private` for kind `ssh`. A client that asked for `private: true` and gets it absent or false MUST treat the reply as a failure (and unregister the tunnel): a server that does not know the field would otherwise expose the tunnel publicly |
| `ssh_jump` | string | optional, kind `ssh` only: `host:port` of the SSH gateway, for `ssh -J <ssh_jump> <user>@<target>`. `<target>` is the client name (tunnel `ssh`) or `<tunnel>-<client>` |
| `inspect` | bool | optional; echoes `register.inspect` when the server stores headers and bodies for this tunnel. A client that asked for `inspect: true` and gets it absent or false SHOULD log a warning and MUST NOT treat it as a failure: the tunnel works, but a server that predates the field records nothing to inspect |

`unregister` (client → server): `{tunnel_id}`. No reply; the server releases the tunnel.

`tunnel_closed` (server → client): `{tunnel_id, reason}` — the server dropped the tunnel.

### 3.2.1 Remote open

A client that sends `"features": ["remote_open"]` in `hello` accepts tunnel requests from the server. The server
never sends `open_request` to a client without the feature (the operator gets `client_unsupported`).

`open_request` (server → client)

| field | type | notes |
|---|---|---|
| `req_id` | int | echoed in `open_result` |
| `kind` | string | `http`, `tcp` or `ssh` |
| `local_addr` | string | `host:port`, a bare port, or `ssh` (= `127.0.0.1:22`) |
| `name` | string | optional |
| `private` | bool | optional, kind `ssh` only |
| `remote_port` | int | optional, kind `tcp` only |
| `requested_by` | string | acting token, for the client log; never an authorization |

`open_result` (client → server): `{req_id, ok, tunnel: {name, kind, public_url, ssh_jump}, error: {code, message}}`.
On `ok` the `tunnel` is set, otherwise the `error`. The client applies its own `allow_remote` policy (error code
`not_allowed`) before it opens anything. The server waits 15 s for the result and then reports `timeout`; a late
result is ignored.

### 3.3 Liveness

`ping` (server → client) `{seq}` every `heartbeat_interval_ms` (default 15000). Client replies `pong {seq}`.
The server closes the session after 3 consecutive missed pongs. The client closes and reconnects if no `ping`
arrives for 3 intervals.

### 3.4 Errors

`error` (either direction)

| field | type | notes |
|---|---|---|
| `req_id` | int | optional; set when replying to a request |
| `code` | string | see below |
| `message` | string | human-readable |
| `retry_after_ms` | int | optional; client must wait at least this long before reconnecting |
| `fatal` | bool | if true, the sender closes the session after sending |

Codes: `unsupported_version`, `unauthorized` (bad/unknown token), `token_expired`, `token_revoked`, `forbidden`
(scope or limit), `name_taken`, `invalid_request`, `port_unavailable`, `limit_exceeded`, `internal`, `shutting_down`,
`session_replaced` (a newer session with the same token took over; sent to the old session), `client_unsupported`,
`timeout`, `not_allowed` (the last three are used in `open_result` and by the admin API).

Clients must not retry automatically on `unauthorized`, `token_expired`, `token_revoked`, `unsupported_version`,
`session_replaced` (otherwise two processes sharing a token would evict each other forever).

## 4. Data streams

For every visitor connection the **server** opens a new yamux stream and writes one frame:

`stream` `{tunnel_id, remote_addr}` — `remote_addr` is the visitor's address (`ip:port`) for logging.

After the header the stream carries raw bytes in both directions. The client dials the local target registered for
`tunnel_id` (deadline 10 s); on failure it closes the stream. Either side closing its write half propagates as EOF.
For HTTP tunnels the bytes are an HTTP/1.1 connection produced by the server's reverse proxy.

## 5. Versioning

The server accepts `protocol_version` N and N-1. For anything else it replies `error{code: unsupported_version,
fatal: true}` naming the supported range in `message`.
