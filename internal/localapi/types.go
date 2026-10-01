// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package localapi is the local control API of the porthole client daemon: HTTP/1.1 + JSON over a unix domain
// socket (see docs/adr/0002-client-daemon-and-tunnels-file.md). It contains the shared JSON types, the HTTP
// handler over a [Backend], the [Client] used by the CLI, socket listen helpers, peer credentials and sd_notify.
//
// The package is independent of internal/client: the daemon implements [Backend] on top of its tunnel manager.
package localapi

import (
	"context"
	"fmt"
	"time"

	"github.com/eto-a/porthole/internal/proto"
)

const (
	// Host is the only Host header value the handler accepts (tailscale does the same with a fixed fake host).
	Host = "porthole"
	// MaxBodyBytes caps every request body.
	MaxBodyBytes = 64 << 10
)

// Error codes. The proto codes are reused where they have the same meaning.
const (
	CodeInvalidRequest = proto.CodeInvalidRequest
	CodeForbidden      = proto.CodeForbidden
	CodeNameTaken      = proto.CodeNameTaken
	CodeInternal       = proto.CodeInternal
	CodeNotFound       = "not_found"
	CodeConflict       = "conflict"
)

// Connection states reported in [Status.State].
const (
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateBackoff    = "backoff"
)

// Tunnel states reported in [Tunnel.State].
const (
	TunnelPending = "pending"
	TunnelReady   = "ready"
	TunnelFailed  = "failed"
)

// Tunnel types.
const (
	TypeHTTP = "http"
	TypeTCP  = "tcp"
	TypeSSH  = "ssh" // reachable through the SSH gateway (with public_port: a tcp tunnel to port 22)
)

// Tunnel sources reported in [Tunnel.Source].
const (
	SourceFile    = "file"
	SourceRuntime = "runtime"
)

// Tunnel lifetimes. [LifetimeFile] only appears in [Tunnel.Lifetime]; requests use attached or runtime.
const (
	LifetimeFile     = "file"
	LifetimeRuntime  = "runtime"  // lives until DELETE or a daemon restart
	LifetimeAttached = "attached" // removed when the request connection closes
)

// Event types.
const (
	EventConnected    = "connected"
	EventDisconnected = "disconnected"
	EventTunnelReady  = "tunnel_ready"
	EventTunnelClosed = "tunnel_closed"
	// EventAttached is only ever the first line of an attached POST /v1/tunnels stream. It carries the accepted
	// tunnel in Event.Tunnel (the name may have been chosen by the daemon).
	EventAttached = "attached"
)

// Error is an API error. It is the JSON body {"error":{"code":...,"message":...}} on the wire and implements error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements error.
func (e *Error) Error() string { return e.Code + ": " + e.Message }

// NewError returns an *Error with a formatted message.
func NewError(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Status is the daemon state returned by GET /v1/status.
type Status struct {
	Version     string     `json:"version"`
	PID         int        `json:"pid"`
	StartedAt   time.Time  `json:"started_at"`
	Server      string     `json:"server"`
	State       string     `json:"state"` // connecting | connected | backoff
	ClientName  string     `json:"client_name"`
	RetryAt     *time.Time `json:"retry_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	TunnelsFile string     `json:"tunnels_file,omitempty"`
	Tunnels     []Tunnel   `json:"tunnels"`
}

// Tunnel describes one tunnel of the daemon.
type Tunnel struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // http | tcp | ssh
	LocalAddr  string `json:"local_addr"`
	RemotePort int    `json:"remote_port,omitempty"`
	PublicURL  string `json:"public_url,omitempty"`
	Private    bool   `json:"private,omitempty"`  // ssh only
	Inspect    bool   `json:"inspect,omitempty"`  // http only: bodies are stored on the server
	SSHJump    string `json:"ssh_jump,omitempty"` // ssh only: host:port of the SSH gateway, once ready
	State      string `json:"state"`              // pending | ready | failed
	Error      string `json:"error,omitempty"`
	Source     string `json:"source"`   // file | runtime
	Lifetime   string `json:"lifetime"` // file | runtime | attached
}

// AddTunnelRequest is the body of POST /v1/tunnels.
type AddTunnelRequest struct {
	Type       string `json:"type"` // http | tcp | ssh
	Name       string `json:"name,omitempty"`
	Addr       string `json:"addr,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Lifetime   string `json:"lifetime,omitempty"` // attached (default) | runtime
	// Private (ssh only) makes the SSH gateway require a porthole token.
	Private bool `json:"private,omitempty"`
	// Inspect (http only) asks the server to store request and response bodies and headers of the tunnel.
	Inspect bool `json:"inspect,omitempty"`
	// PublicPort (ssh only) selects the v0.1 mode: a public TCP port instead of the gateway. RemotePort is only
	// valid together with it.
	PublicPort bool `json:"public_port,omitempty"`
}

// ReloadResult is the outcome of POST /v1/reload: tunnel names by what the reload did to them.
type ReloadResult struct {
	Added     []string          `json:"added"`
	Removed   []string          `json:"removed"`
	Changed   []string          `json:"changed"`
	Unchanged []string          `json:"unchanged"`
	Errors    map[string]string `json:"errors,omitempty"` // per-tunnel failures
}

// Event is one line of the /v1/events stream and of an attached POST /v1/tunnels stream.
type Event struct {
	Type       string    `json:"type"` // connected | disconnected | tunnel_ready | tunnel_closed | attached
	Name       string    `json:"name,omitempty"`
	PublicURL  string    `json:"public_url,omitempty"`
	SSHJump    string    `json:"ssh_jump,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	ClientName string    `json:"client_name,omitempty"`
	Error      string    `json:"error,omitempty"`
	RetryInMS  int64     `json:"retry_in_ms,omitempty"`
	Time       time.Time `json:"time"`
	Tunnel     *Tunnel   `json:"tunnel,omitempty"` // only for EventAttached
}

// Backend is what the daemon implements and the handler serves. All methods must be safe for concurrent use.
type Backend interface {
	// Status returns the current daemon state.
	Status(ctx context.Context) Status
	// Tunnels returns all tunnels (file and runtime), ordered by name.
	Tunnels(ctx context.Context) []Tunnel
	// AddTunnel adds a tunnel to the set and returns quickly, once the tunnel is accepted; its state may still
	// be pending. Validation problems and name conflicts are returned as *Error (invalid_request, name_taken,
	// conflict). req.Lifetime is "attached" or "runtime" (the handler has validated it); the tunnel's
	// Lifetime field reports it back.
	AddTunnel(ctx context.Context, req AddTunnelRequest) (Tunnel, error)
	// RemoveTunnel removes a tunnel by name. It returns *Error with not_found, or conflict for tunnels that
	// come from the tunnels file.
	RemoveTunnel(ctx context.Context, name string) error
	// Reload re-reads the tunnels file and applies the difference. A broken file keeps the old set and is
	// reported as an *Error (invalid_request); per-tunnel failures go to ReloadResult.Errors.
	Reload(ctx context.Context) (ReloadResult, error)
	// Subscribe returns a stream of events. The channel is closed when ctx is done. Delivery is best effort: a
	// consumer that does not keep up may miss events (the backend must never block on a slow consumer). A
	// failed registration of a tunnel is reported as EventTunnelClosed with Error set.
	Subscribe(ctx context.Context) <-chan Event
}
