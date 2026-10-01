// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package proto implements the porthole control protocol described in docs/protocol.md:
// length-prefixed JSON frames exchanged on the control stream and at the start of data streams.
package proto

// Version is the protocol version spoken by this build.
const Version = 1

// MinVersion is the oldest protocol version this build accepts (N-1 policy).
const MinVersion = 1

// WebSocket endpoint and subprotocol of the client session.
const (
	ConnectPath    = "/_porthole/v1/connect"
	WSSubprotocol  = "porthole.v1"
	DefaultHBMilli = 15000
)

// Tunnel kinds.
const (
	KindHTTP = "http"
	KindTCP  = "tcp"
	KindUDP  = "udp" // reserved for v0.2
	KindSSH  = "ssh" // reachable only through the server's SSH gateway; no public listener
)

// Error codes carried in Error.Code.
const (
	CodeUnsupportedVersion = "unsupported_version"
	CodeUnauthorized       = "unauthorized"
	CodeTokenExpired       = "token_expired"
	CodeTokenRevoked       = "token_revoked"
	CodeForbidden          = "forbidden"
	CodeNameTaken          = "name_taken"
	CodeInvalidRequest     = "invalid_request"
	CodePortUnavailable    = "port_unavailable"
	CodeLimitExceeded      = "limit_exceeded"
	CodeInternal           = "internal"
	CodeShuttingDown       = "shutting_down"
	CodeSessionReplaced    = "session_replaced"
)

// Message is implemented by every protocol message.
type Message interface {
	// MsgType returns the value of the "type" field on the wire.
	MsgType() string
}

// Hello is the first message of a session (client → server).
type Hello struct {
	ProtocolVersion int    `json:"protocol_version"`
	Token           string `json:"token"`
	ClientVersion   string `json:"client_version,omitempty"`
	OS              string `json:"os,omitempty"`
}

// HelloOK accepts a session (server → client).
type HelloOK struct {
	SessionID           string `json:"session_id"`
	ClientName          string `json:"client_name"`
	ServerVersion       string `json:"server_version,omitempty"`
	HeartbeatIntervalMS int    `json:"heartbeat_interval_ms"`
}

// Register asks the server to create a tunnel (client → server).
type Register struct {
	ReqID      int    `json:"req_id"`
	Kind       string `json:"kind"`
	Name       string `json:"name,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	// Private (kind ssh only) makes the gateway require a porthole token before it opens the tunnel.
	Private bool `json:"private,omitempty"`
}

// Registered confirms a tunnel and carries its public address (server → client).
type Registered struct {
	ReqID     int    `json:"req_id"`
	TunnelID  string `json:"tunnel_id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	PublicURL string `json:"public_url"`
	// Private echoes Register.Private. A client that asked for a private tunnel and gets false back is talking to
	// a server that ignored the field and must treat the reply as a failure.
	Private bool `json:"private,omitempty"`
	// SSHJump is the host:port of the SSH gateway (kind ssh only).
	SSHJump string `json:"ssh_jump,omitempty"`
}

// Unregister releases a tunnel (client → server).
type Unregister struct {
	TunnelID string `json:"tunnel_id"`
}

// TunnelClosed tells the client that the server dropped a tunnel (server → client).
type TunnelClosed struct {
	TunnelID string `json:"tunnel_id"`
	Reason   string `json:"reason,omitempty"`
}

// Ping is a liveness probe (server → client).
type Ping struct {
	Seq uint64 `json:"seq"`
}

// Pong answers a Ping (client → server).
type Pong struct {
	Seq uint64 `json:"seq"`
}

// Error reports a failure (either direction).
type Error struct {
	ReqID        int    `json:"req_id,omitempty"`
	Code         string `json:"code"`
	Message      string `json:"message,omitempty"`
	RetryAfterMS int    `json:"retry_after_ms,omitempty"`
	Fatal        bool   `json:"fatal,omitempty"`
}

// Error implements the error interface so a received *Error can be returned directly.
func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Retryable reports whether a client may reconnect automatically after this error.
func (e *Error) Retryable() bool {
	switch e.Code {
	case CodeUnauthorized, CodeTokenExpired, CodeTokenRevoked, CodeUnsupportedVersion, CodeSessionReplaced:
		return false
	}
	return true
}

// StreamHeader is the first frame of every data stream (server → client).
type StreamHeader struct {
	TunnelID   string `json:"tunnel_id"`
	RemoteAddr string `json:"remote_addr,omitempty"`
}

func (*Hello) MsgType() string        { return "hello" }
func (*HelloOK) MsgType() string      { return "hello_ok" }
func (*Register) MsgType() string     { return "register" }
func (*Registered) MsgType() string   { return "registered" }
func (*Unregister) MsgType() string   { return "unregister" }
func (*TunnelClosed) MsgType() string { return "tunnel_closed" }
func (*Ping) MsgType() string         { return "ping" }
func (*Pong) MsgType() string         { return "pong" }
func (*Error) MsgType() string        { return "error" }
func (*StreamHeader) MsgType() string { return "stream" }

// newMessage returns an empty message for a wire type, or nil if the type is unknown.
func newMessage(typ string) Message {
	switch typ {
	case "hello":
		return &Hello{}
	case "hello_ok":
		return &HelloOK{}
	case "register":
		return &Register{}
	case "registered":
		return &Registered{}
	case "unregister":
		return &Unregister{}
	case "tunnel_closed":
		return &TunnelClosed{}
	case "ping":
		return &Ping{}
	case "pong":
		return &Pong{}
	case "error":
		return &Error{}
	case "stream":
		return &StreamHeader{}
	}
	return nil
}
