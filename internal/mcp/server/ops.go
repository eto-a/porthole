// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package server is the operator MCP server (ADR 0005, surface A): the tools an agent uses to look after a
// porthole server. The tools run over the Ops interface, which has an in-process implementation over the admin API's
// Backend and Store (LocalOps, used by the HTTP endpoint), one over the admin unix socket (SocketOps, used by
// `portholed mcp`), and later one over the bearer HTTP API.
package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
)

// ErrNotImplemented is returned by an Ops method the implementation cannot serve yet. Its text goes to the model.
var ErrNotImplemented = errors.New("not implemented yet")

// InvalidArgError is an Ops or tool error caused by the caller's arguments; its text goes to the model as is.
type InvalidArgError string

func (e InvalidArgError) Error() string { return string(e) }

// Ops is everything the operator tools need. Implementations must be safe for concurrent use. Methods that cannot
// be served return an error wrapping ErrNotImplemented; unknown clients, tunnels, tokens and requests are
// adminapi.ErrNotFound.
type Ops interface {
	Status(ctx context.Context) (adminapi.Status, error)

	Clients(ctx context.Context) ([]adminapi.Client, error)
	DisconnectClient(ctx context.Context, name string) error

	Tunnels(ctx context.Context) ([]adminapi.Tunnel, error)
	CloseTunnel(ctx context.Context, id string) error
	// RequestTunnel asks a connected client to open a tunnel (ADR 0005, remote tunnel requests).
	RequestTunnel(ctx context.Context, p RequestTunnelParams) (RequestTunnelResult, error)

	Tokens(ctx context.Context) ([]adminapi.Token, error)
	RevokeToken(ctx context.Context, id string) error
	// CreateJoinLink creates a single-use join link; it never returns a long-lived token.
	CreateJoinLink(ctx context.Context, p JoinLinkParams) (JoinLink, error)

	QueryRequests(ctx context.Context, q RequestQuery) (RequestsResult, error)
	// GetRequest returns one request with its Detail (when the request was inspected). The caller drops the Detail
	// unless the token holds admin:traffic.
	GetRequest(ctx context.Context, id uint64) (Request, error)
	// ReplayRequest sends a recorded, inspected request into its tunnel again and returns the new log entry.
	ReplayRequest(ctx context.Context, id uint64) (Request, error)
	ConnectionLog(ctx context.Context, q ConnQuery) ([]Conn, error)
	GatewayAuthFailures(ctx context.Context, since time.Time, limit int) ([]Conn, error)

	AuditLog(ctx context.Context, limit int) ([]adminapi.AuditEntry, error)
}

// RequestTunnelParams describes a tunnel to open on a connected client.
type RequestTunnelParams struct {
	Client    string `json:"client"`
	Kind      string `json:"kind"` // http | tcp | ssh
	LocalAddr string `json:"local_addr"`
	Name      string `json:"name,omitempty"`
	Private   bool   `json:"private,omitempty"`
}

// RequestTunnelResult is the tunnel the client opened.
type RequestTunnelResult struct {
	Tunnel adminapi.RemoteTunnel `json:"tunnel"`
}

// JoinLinkParams describes a join link.
type JoinLinkParams struct {
	Client      string        `json:"client"`
	Scopes      []string      `json:"scopes,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
	AllowRemote bool          `json:"allow_remote"`
}

// JoinLink is a created join link. Command is what to run on the machine.
type JoinLink struct {
	URL       string    `json:"url"`
	Command   string    `json:"command"`
	Client    string    `json:"client"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RequestQuery filters the request log; zero fields do not filter.
type RequestQuery struct {
	Tunnel      string
	Client      string
	StatusClass int // 2..5
	PathPrefix  string
	IP          string
	Since       time.Time
	Limit       int
	// Aggregate also summarises every matching request.
	Aggregate bool
	TopN      int
}

// RequestsResult is the answer to QueryRequests: matching requests, newest first, and optionally their summary.
type RequestsResult struct {
	Requests   []Request   `json:"requests"`
	Aggregates *Aggregates `json:"aggregates,omitempty"`
}

// Request is one proxied HTTP request from the request log.
type Request struct {
	ID        uint64    `json:"id"`
	Time      time.Time `json:"time"`
	TunnelID  string    `json:"tunnel_id,omitempty"`
	Tunnel    string    `json:"tunnel,omitempty"`
	Client    string    `json:"client,omitempty"`
	VisitorIP string    `json:"visitor_ip"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Query     string    `json:"query,omitempty"`
	Status    int       `json:"status"`
	LatencyMS float64   `json:"latency_ms"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	UserAgent string    `json:"user_agent,omitempty"`
	Referer   string    `json:"referer,omitempty"`
	ReplayOf  uint64    `json:"replay_of,omitempty"`
	// HasDetail says that headers and bodies were stored; get_request returns them as Detail to holders of admin:traffic.
	HasDetail bool           `json:"has_detail,omitempty"`
	Detail    *RequestDetail `json:"detail,omitempty"`
}

// Count is a key with the number of requests that had it.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Aggregates summarises a set of requests.
type Aggregates struct {
	Total         int            `json:"total"`
	StatusClasses map[string]int `json:"status_classes"`
	TopPaths      []Count        `json:"top_paths"`
	TopVisitors   []Count        `json:"top_visitors"`
	LatencyMS     Latency        `json:"latency_ms"`
	PerMinute     []Bucket       `json:"per_minute"`
}

// Latency holds latency percentiles in milliseconds.
type Latency struct {
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
	P99 float64 `json:"p99"`
}

// Bucket is the number of requests in one minute.
type Bucket struct {
	Minute time.Time `json:"minute"`
	Count  int       `json:"count"`
}

// ConnQuery filters the connection log (TCP tunnels and the SSH gateway); zero fields do not filter.
type ConnQuery struct {
	Tunnel  string
	Client  string
	Kind    string // tcp | ssh
	IP      string
	Outcome string // ok | refused | auth_failed | limit
	Since   time.Time
	Limit   int
}

// Conn is one visitor connection to a TCP tunnel or the SSH gateway: metadata only.
type Conn struct {
	ID         uint64    `json:"id"`
	Start      time.Time `json:"start"`
	DurationMS float64   `json:"duration_ms"`
	TunnelID   string    `json:"tunnel_id,omitempty"`
	Tunnel     string    `json:"tunnel,omitempty"`
	Client     string    `json:"client,omitempty"`
	Kind       string    `json:"kind"`
	VisitorIP  string    `json:"visitor_ip"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	Outcome    string    `json:"outcome"`
}

// RequestDetail is what an inspected request kept: headers (Authorization, cookies masked) and the first bytes of
// the bodies.
type RequestDetail struct {
	RequestHeaders  http.Header `json:"request_headers"`
	RequestBody     Body        `json:"request_body"`
	ResponseHeaders http.Header `json:"response_headers"`
	ResponseBody    Body        `json:"response_body"`
}

// Body is a captured body: text when it is valid UTF-8, base64 otherwise, and the real size.
type Body struct {
	Text      string `json:"text,omitempty"`
	Base64    string `json:"base64,omitempty"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated,omitempty"`
}
