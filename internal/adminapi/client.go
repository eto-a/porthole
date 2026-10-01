// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/eto-a/porthole/internal/traffic"
)

const (
	clientTimeout    = 30 * time.Second // a remote tunnel request waits for the client
	maxResponseBytes = 4 << 20
)

// SocketClient calls the admin API over the unix socket (no token needed).
type SocketClient struct {
	hc *http.Client
}

// NewSocketClient returns a SocketClient that talks to the admin socket at path.
func NewSocketClient(path string) *SocketClient {
	return &SocketClient{hc: &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}}
}

// Status calls GET status.
func (c *SocketClient) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.get(ctx, "/status", &s)
	return s, err
}

// Clients calls GET clients.
func (c *SocketClient) Clients(ctx context.Context) ([]Client, error) {
	var r struct {
		Clients []Client `json:"clients"`
	}
	err := c.get(ctx, "/clients", &r)
	return r.Clients, err
}

// Tunnels calls GET tunnels.
func (c *SocketClient) Tunnels(ctx context.Context) ([]Tunnel, error) {
	var r struct {
		Tunnels []Tunnel `json:"tunnels"`
	}
	err := c.get(ctx, "/tunnels", &r)
	return r.Tunnels, err
}

// Tokens calls GET tokens.
func (c *SocketClient) Tokens(ctx context.Context) ([]Token, error) {
	var r struct {
		Tokens []Token `json:"tokens"`
	}
	err := c.get(ctx, "/tokens", &r)
	return r.Tokens, err
}

// Audit calls GET audit; limit 0 is the server's default.
func (c *SocketClient) Audit(ctx context.Context, limit int) ([]AuditEntry, error) {
	var r struct {
		Entries []AuditEntry `json:"entries"`
	}
	path := "/audit"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	err := c.get(ctx, path, &r)
	return r.Entries, err
}

// Disconnect calls POST clients/{name}/disconnect.
func (c *SocketClient) Disconnect(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(name)+"/disconnect", nil, &struct{}{})
}

// CloseTunnel calls DELETE tunnels/{id}.
func (c *SocketClient) CloseTunnel(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/tunnels/"+url.PathEscape(id), nil, &struct{}{})
}

// ReleaseLabel calls POST labels/{label}/release.
func (c *SocketClient) ReleaseLabel(ctx context.Context, label string) error {
	return c.do(ctx, http.MethodPost, "/labels/"+url.PathEscape(label)+"/release", nil, &struct{}{})
}

// RevokeToken calls POST tokens/{id}/revoke.
func (c *SocketClient) RevokeToken(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/tokens/"+url.PathEscape(id)+"/revoke", nil, &struct{}{})
}

// Error is an error response of the API.
type Error struct {
	HTTPStatus int
	Code       string
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("admin api: %s: %s (HTTP %d)", e.Code, e.Message, e.HTTPStatus)
}

// CreateJoin calls POST join: it stores a one-time join code and returns its link.
func (c *SocketClient) CreateJoin(ctx context.Context, req JoinRequest) (JoinCreated, error) {
	var out JoinCreated
	err := c.do(ctx, http.MethodPost, "/join", req, &out)
	return out, err
}

// ListJoin calls GET join.
func (c *SocketClient) ListJoin(ctx context.Context) ([]JoinCode, error) {
	var out struct {
		Codes []JoinCode `json:"join_codes"`
	}
	err := c.get(ctx, "/join", &out)
	return out.Codes, err
}

// RevokeJoin calls POST join/{id}/revoke.
func (c *SocketClient) RevokeJoin(ctx context.Context, id string) error {
	var out map[string]bool
	return c.do(ctx, http.MethodPost, "/join/"+url.PathEscape(id)+"/revoke", nil, &out)
}

func (c *SocketClient) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *SocketClient) do(ctx context.Context, method, path string, in, out any) error {
	var reqBody io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("admin api: encode request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	// The host is a placeholder: the dialer ignores it and connects to the socket.
	req, err := http.NewRequestWithContext(ctx, method, "http://porthole-admin"+Prefix+path, reqBody)
	if err != nil {
		return fmt.Errorf("admin api: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("admin api: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("admin api: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var eb ErrorBody
		if json.Unmarshal(data, &eb) != nil || eb.Error.Code == "" {
			return &Error{HTTPStatus: resp.StatusCode, Code: "http_error", Message: http.StatusText(resp.StatusCode)}
		}
		return &Error{HTTPStatus: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("admin api: decode response: %w", err)
	}
	return nil
}

// RequestTunnel calls POST clients/{name}/tunnels: the named client opens a tunnel and the call returns its address.
// Failures are *Error with the codes of RemoteError (and "not_found" for an offline client).
func (c *SocketClient) RequestTunnel(ctx context.Context, client string, req RemoteOpen) (RemoteTunnel, error) {
	var out struct {
		Tunnel RemoteTunnel `json:"tunnel"`
	}
	if err := c.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(client)+"/tunnels", req, &out); err != nil {
		return RemoteTunnel{}, err
	}
	return out.Tunnel, nil
}

// Requests calls GET requests: the logged HTTP requests matching f, newest first, without details.
func (c *SocketClient) Requests(ctx context.Context, f traffic.RequestFilter) ([]traffic.Request, error) {
	var out struct {
		Requests []traffic.Request `json:"requests"`
	}
	err := c.get(ctx, "/requests"+requestQuery(f, false, 0), &out)
	return out.Requests, err
}

// RequestAggregates calls GET requests?aggregate=1: a summary of the requests matching f.
func (c *SocketClient) RequestAggregates(ctx context.Context, f traffic.RequestFilter, topN int) (traffic.Aggregates, error) {
	var out struct {
		Aggregates traffic.Aggregates `json:"aggregates"`
	}
	err := c.get(ctx, "/requests"+requestQuery(f, true, topN), &out)
	return out.Aggregates, err
}

// Request calls GET requests/{id}. The socket is fully trusted, so the result carries its Detail.
func (c *SocketClient) Request(ctx context.Context, id uint64) (traffic.Request, error) {
	var out traffic.Request
	err := c.get(ctx, "/requests/"+strconv.FormatUint(id, 10), &out)
	return out, err
}

// ReplayRequest calls POST requests/{id}/replay and returns the new log entry.
func (c *SocketClient) ReplayRequest(ctx context.Context, id uint64) (traffic.Request, error) {
	var out traffic.Request
	err := c.do(ctx, http.MethodPost, "/requests/"+strconv.FormatUint(id, 10)+"/replay", nil, &out)
	return out, err
}

// Connections calls GET connections: the logged TCP and SSH connections matching f, newest first.
func (c *SocketClient) Connections(ctx context.Context, f traffic.ConnFilter) ([]traffic.Conn, error) {
	q := url.Values{}
	setStr(q, "tunnel", f.Tunnel)
	setStr(q, "client", f.Client)
	setStr(q, "kind", f.Kind)
	setStr(q, "ip", f.IP)
	setStr(q, "outcome", f.Outcome)
	setSince(q, f.Since)
	setInt(q, "limit", f.Limit)
	var out struct {
		Connections []traffic.Conn `json:"connections"`
	}
	err := c.get(ctx, "/connections"+encodeQuery(q), &out)
	return out.Connections, err
}

// AuthFailures calls GET auth-failures: SSH gateway authentication failures since the given time, newest first.
func (c *SocketClient) AuthFailures(ctx context.Context, since time.Time, limit int) ([]traffic.Conn, error) {
	q := url.Values{}
	setSince(q, since)
	setInt(q, "limit", limit)
	var out struct {
		Failures []traffic.Conn `json:"auth_failures"`
	}
	err := c.get(ctx, "/auth-failures"+encodeQuery(q), &out)
	return out.Failures, err
}

func requestQuery(f traffic.RequestFilter, aggregate bool, topN int) string {
	q := url.Values{}
	setStr(q, "tunnel", f.Tunnel)
	setStr(q, "client", f.Client)
	setStr(q, "path_prefix", f.PathPrefix)
	setStr(q, "ip", f.IP)
	setInt(q, "status_class", f.StatusClass)
	setSince(q, f.Since)
	setInt(q, "limit", f.Limit)
	if aggregate {
		q.Set("aggregate", "1")
		setInt(q, "top", topN)
	}
	return encodeQuery(q)
}

func setStr(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func setInt(q url.Values, k string, v int) {
	if v != 0 {
		q.Set(k, strconv.Itoa(v))
	}
}

func setSince(q url.Values, t time.Time) {
	if !t.IsZero() {
		q.Set("since", t.UTC().Format(time.RFC3339))
	}
}

func encodeQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}
