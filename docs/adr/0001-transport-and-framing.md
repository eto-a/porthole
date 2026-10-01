# 0001. Transport and control framing for v0.1

- Status: accepted
- Date: 2026-10-01

## Context

The client must reach the server from restrictive networks (outbound TLS on 443 only, sometimes via HTTP proxies),
multiplex many proxied connections over one session, and later carry UDP. Candidates studied: frp (TCP/TLS/KCP/QUIC/
WS + fatedier/yamux, JSON messages), rathole (one TCP connection per data channel, bincode), chisel (SSH over
WebSocket), sish (plain SSH), bore (TCP, NUL-delimited JSON), cloudflared (QUIC + HTTP/2 fallback, Cap'n Proto).

## Decision

- v0.1 transport: WebSocket (`github.com/coder/websocket`) over TLS on port 443, wrapped as `net.Conn`, multiplexed
  with `github.com/hashicorp/yamux`. One control stream opened by the client; one stream per visitor connection
  opened by the server.
- v0.2 adds QUIC (`quic-go`) as the primary transport behind the same `transport.Session` interface, with automatic
  fallback to WebSocket, and uses QUIC datagrams for UDP.
- Control framing: `uint32` big-endian length + JSON object with a `type` field, max 64 KiB per frame.

## Consequences

- Works through HTTP proxies and shares the HTTP listener and certificate; no UDP needed in v0.1.
- TCP head-of-line blocking affects all streams of a session on lossy links until QUIC lands.
- JSON costs CPU only on the control path (rare messages); data streams carry raw bytes.
- yamux is MPL-2.0: compatible with an Apache-2.0 project as an unmodified dependency.

## Alternatives rejected

- SSH as control protocol (chisel, sish): ties auth to SSH users/keys instead of revocable server tokens; awkward UDP.
- One TCP connection per data channel (rathole, frp without mux): extra handshakes and connection pools that leak.
- Cap'n Proto / protobuf: extra toolchain for ~10 message types; can be revisited if the message set grows.
- gorilla/websocket: no releases since 2024.
