// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/store"
)

const testTimeout = 10 * time.Second

// fakeOps records the arguments of the calls and serves canned data.
type fakeOps struct {
	mu       sync.Mutex
	closed   []string
	revoked  []string
	gotQuery RequestQuery
	gotConn  ConnQuery
	tunnels  []adminapi.Tunnel

	gotOpen  RequestTunnelParams
	openErr  error
	gotJoin  JoinLinkParams
	replayed []uint64
}

func newFakeOps() *fakeOps {
	return &fakeOps{tunnels: []adminapi.Tunnel{
		{ID: "t1", Client: "home", Name: "blog", Kind: "http", URL: "https://blog.example.com"},
		{ID: "t2", Client: "office", Name: "db", Kind: "tcp", Port: 20001},
	}}
}

func (f *fakeOps) Status(context.Context) (adminapi.Status, error) {
	return adminapi.Status{Version: "v9", Clients: 2, Tunnels: 2}, nil
}

func (f *fakeOps) Clients(context.Context) ([]adminapi.Client, error) { return nil, nil }

func (f *fakeOps) DisconnectClient(context.Context, string) error { return adminapi.ErrNotFound }

func (f *fakeOps) Tunnels(context.Context) ([]adminapi.Tunnel, error) { return f.tunnels, nil }

func (f *fakeOps) CloseTunnel(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == "nope" {
		return adminapi.ErrNotFound
	}
	f.closed = append(f.closed, id)
	return nil
}

func (f *fakeOps) RequestTunnel(_ context.Context, p RequestTunnelParams) (RequestTunnelResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotOpen = p
	if f.openErr != nil {
		return RequestTunnelResult{}, f.openErr
	}
	return RequestTunnelResult{Tunnel: adminapi.RemoteTunnel{Name: p.Name, Kind: p.Kind, URL: "https://web-home.example.com"}}, nil
}

func (f *fakeOps) Tokens(context.Context) ([]adminapi.Token, error) { return nil, nil }

func (f *fakeOps) RevokeToken(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, id)
	return nil
}

func (f *fakeOps) CreateJoinLink(_ context.Context, p JoinLinkParams) (JoinLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotJoin = p
	return JoinLink{URL: "https://example.com/j/abc", Command: "porthole join https://example.com/j/abc", Client: p.Client}, nil
}

func (f *fakeOps) ReplayRequest(_ context.Context, id uint64) (Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replayed = append(f.replayed, id)
	return Request{ID: 8, ReplayOf: id}, nil
}

func (f *fakeOps) QueryRequests(_ context.Context, q RequestQuery) (RequestsResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotQuery = q
	res := RequestsResult{Requests: []Request{{ID: 7, Path: "/wp-admin", Status: 404, LatencyMS: 1.5}}}
	if q.Aggregate {
		res.Aggregates = &Aggregates{Total: 1, StatusClasses: map[string]int{"4xx": 1}}
	}
	return res, nil
}

func (f *fakeOps) GetRequest(context.Context, uint64) (Request, error) {
	return Request{ID: 7, HasDetail: true, Detail: &RequestDetail{RequestHeaders: http.Header{"X-Probe": {"1"}}, ResponseHeaders: http.Header{}}}, nil
}

func (f *fakeOps) ConnectionLog(_ context.Context, q ConnQuery) ([]Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotConn = q
	return nil, nil
}

func (f *fakeOps) GatewayAuthFailures(context.Context, time.Time, int) ([]Conn, error) {
	return nil, nil
}

func (f *fakeOps) AuditLog(context.Context, int) ([]adminapi.AuditEntry, error) { return nil, nil }

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// connect serves srv over in-memory transports and returns the client session.
func connect(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := ctxT(t)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(ctxT(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

func newServer(t *testing.T, ops Ops, opts Options) *mcp.Server {
	t.Helper()
	srv, err := New(ops, opts)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestToolsets(t *testing.T) {
	all := []string{
		"audit_log", "close_tunnel", "connection_log", "create_join_link", "disconnect_client", "gateway_auth_failures",
		"get_request", "list_clients", "list_tokens", "list_tunnels", "query_requests", "replay_request", "request_tunnel", "revoke_token",
		"server_status",
	}
	mutating := []string{"close_tunnel", "create_join_link", "disconnect_client", "replay_request", "request_tunnel", "revoke_token"}
	tests := []struct {
		name string
		opts Options
		want []string
	}{
		{"all", Options{}, all},
		{"read-only hides every mutating tool", Options{ReadOnly: true}, slices.DeleteFunc(slices.Clone(all), func(n string) bool { return slices.Contains(mutating, n) })},
		{"toolsets filter", Options{Toolsets: []string{ToolsetTunnels, ToolsetStatus}}, []string{"close_tunnel", "list_tunnels", "request_tunnel", "server_status"}},
		{"read-only wins over toolsets", Options{Toolsets: []string{ToolsetTunnels, ToolsetClients}, ReadOnly: true}, []string{"list_clients", "list_tunnels"}},
		{"traffic", Options{Toolsets: []string{ToolsetTraffic}}, []string{"connection_log", "gateway_auth_failures", "get_request", "query_requests", "replay_request"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toolNames(t, connect(t, newServer(t, newFakeOps(), tc.opts)))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("tools = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAnnotations(t *testing.T) {
	cs := connect(t, newServer(t, newFakeOps(), Options{}))
	res, err := cs.ListTools(ctxT(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		mut := slices.Contains([]string{"close_tunnel", "create_join_link", "disconnect_client", "replay_request", "request_tunnel", "revoke_token"}, tl.Name)
		if tl.Annotations == nil || tl.Annotations.ReadOnlyHint == mut {
			t.Errorf("%s: ReadOnlyHint = %v, want %v", tl.Name, tl.Annotations != nil && tl.Annotations.ReadOnlyHint, !mut)
		}
	}
}

func TestParseToolsets(t *testing.T) {
	got, err := ParseToolsets("tunnels, status,tunnels")
	if err != nil || !slices.Equal(got, []string{"tunnels", "status"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := ParseToolsets("all"); err != nil || got != nil {
		t.Fatalf("all: got %v, %v", got, err)
	}
	if _, err := ParseToolsets("tunnels,bogus"); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("unknown toolset: err = %v", err)
	}
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(ctxT(t), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func decode(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", text(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func text(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestCalls(t *testing.T) {
	ops := newFakeOps()
	cs := connect(t, newServer(t, ops, Options{}))

	var tl tunnelsOut
	decode(t, call(t, cs, "list_tunnels", map[string]any{}), &tl)
	if len(tl.Tunnels) != 2 {
		t.Fatalf("list_tunnels: %+v", tl)
	}
	decode(t, call(t, cs, "list_tunnels", map[string]any{"client": "home"}), &tl)
	if len(tl.Tunnels) != 1 || tl.Tunnels[0].ID != "t1" {
		t.Fatalf("list_tunnels client=home: %+v", tl)
	}

	var ar ActionResult
	decode(t, call(t, cs, "close_tunnel", map[string]any{"id": "t1"}), &ar)
	if !ar.OK || !slices.Equal(ops.closed, []string{"t1"}) {
		t.Fatalf("close_tunnel: %+v closed=%v", ar, ops.closed)
	}
	res := call(t, cs, "close_tunnel", map[string]any{"id": "nope"})
	if !res.IsError || text(res) != "not found" {
		t.Fatalf("close_tunnel nope: isError=%v %q", res.IsError, text(res))
	}

	var rr RequestsResult
	decode(t, call(t, cs, "query_requests", map[string]any{
		"tunnel": "blog", "status_class": 4, "path_prefix": "/wp", "since": "15m", "aggregate": true, "limit": 5000,
	}), &rr)
	q := ops.gotQuery
	if q.Tunnel != "blog" || q.StatusClass != 4 || q.PathPrefix != "/wp" || !q.Aggregate || q.Limit != maxListLimit || q.TopN != defaultTopN {
		t.Fatalf("query passed to Ops: %+v", q)
	}
	if d := time.Since(q.Since); d < 14*time.Minute || d > 16*time.Minute {
		t.Fatalf("since = %v ago, want about 15m", d)
	}
	if len(rr.Requests) != 1 || rr.Aggregates == nil || rr.Aggregates.Total != 1 {
		t.Fatalf("query_requests result: %+v", rr)
	}

	res = call(t, cs, "query_requests", map[string]any{"status_class": 9})
	if !res.IsError || !strings.Contains(text(res), "status_class") {
		t.Fatalf("bad status_class: %q", text(res))
	}
	var jl JoinLink
	decode(t, call(t, cs, "create_join_link", map[string]any{"client": "laptop", "ttl_minutes": 30, "allow_remote": false}), &jl)
	if jl.Command == "" || ops.gotJoin.Client != "laptop" || ops.gotJoin.TTL != 30*time.Minute || ops.gotJoin.AllowRemote {
		t.Fatalf("create_join_link: %+v, params %+v", jl, ops.gotJoin)
	}

	var rt RequestTunnelResult
	decode(t, call(t, cs, "request_tunnel", map[string]any{"client": "home", "kind": "http", "local_addr": "8080", "name": "web"}), &rt)
	if rt.Tunnel.URL != "https://web-home.example.com" || ops.gotOpen != (RequestTunnelParams{Client: "home", Kind: "http", LocalAddr: "8080", Name: "web"}) {
		t.Fatalf("request_tunnel: %+v, params %+v", rt, ops.gotOpen)
	}
	ops.openErr = &adminapi.RemoteError{Code: adminapi.CodeRemoteDisabled, Message: "remote control is not enabled for this client"}
	res = call(t, cs, "request_tunnel", map[string]any{"client": "home", "kind": "http", "local_addr": "8080"})
	if !res.IsError || !strings.Contains(text(res), adminapi.CodeRemoteDisabled) || !strings.Contains(text(res), "not enabled") {
		t.Fatalf("remote refusal must reach the model with code and text: %q", text(res))
	}
	ops.openErr = adminapi.ErrNotFound
	res = call(t, cs, "request_tunnel", map[string]any{"client": "gone", "kind": "tcp", "local_addr": "22"})
	if !res.IsError || !strings.Contains(text(res), "not connected") {
		t.Fatalf("offline client: %q", text(res))
	}

	var rep Request
	decode(t, call(t, cs, "replay_request", map[string]any{"id": 7}), &rep)
	if rep.ID != 8 || rep.ReplayOf != 7 || len(ops.replayed) != 1 || ops.replayed[0] != 7 {
		t.Fatalf("replay_request: %+v, replayed %v", rep, ops.replayed)
	}
}

// get_request returns headers and bodies only to a caller that holds admin:traffic.
func TestGetRequestDetailNeedsTrafficScope(t *testing.T) {
	ts := httpEnv(t, newFakeOps(), nil)
	var r Request
	decode(t, call(t, httpSession(t, ts, "reader"), "get_request", map[string]any{"id": 7}), &r)
	if r.ID != 7 || r.Detail != nil {
		t.Fatalf("without admin:traffic: %+v", r)
	}
	decode(t, call(t, httpSession(t, ts, "traffic"), "get_request", map[string]any{"id": 7}), &r)
	if r.Detail == nil || r.Detail.RequestHeaders.Get("X-Probe") != "1" {
		t.Fatalf("with admin:traffic: %+v", r)
	}
	// The stdio server over the admin socket has no token and is trusted.
	decode(t, call(t, connect(t, newServer(t, newFakeOps(), Options{})), "get_request", map[string]any{"id": 7}), &r)
	if r.Detail == nil {
		t.Fatal("trusted caller got no detail")
	}
}

// fakeAudit collects audit entries.
type fakeAudit struct {
	mu      sync.Mutex
	entries []store.AuditEntry
}

func (a *fakeAudit) AppendAudit(_ context.Context, e *store.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, *e)
	return nil
}

func (a *fakeAudit) get() []store.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.entries)
}

// httpEnv serves the endpoint with a map of bearer secrets to tokens.
func httpEnv(t *testing.T, ops Ops, aud Auditor) *httptest.Server {
	t.Helper()
	toks := map[string]*store.Token{
		"reader":  {ID: "tok_r", Scopes: []string{auth.ScopeAdminRead}},
		"tunnels": {ID: "tok_t", Scopes: []string{auth.ScopeAdminRead, auth.ScopeAdminTunnels}},
		"traffic": {ID: "tok_x", Scopes: []string{auth.ScopeAdminRead, auth.ScopeAdminTraffic}},
	}
	h, err := NewHTTPHandler(ops, Options{Audit: aud}, HTTPOptions{
		Authenticate: func(_ context.Context, _, raw string) (*store.Token, error) {
			if tok, ok := toks[raw]; ok {
				return tok, nil
			}
			return nil, adminapi.ErrUnauthorized
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(Path, h)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

type bearerTransport struct{ secret string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.secret)
	return http.DefaultTransport.RoundTrip(r)
}

func httpSession(t *testing.T, ts *httptest.Server, secret string) *mcp.ClientSession {
	t.Helper()
	ct := &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + Path,
		HTTPClient:           &http.Client{Transport: bearerTransport{secret}},
		DisableStandaloneSSE: true,
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctxT(t), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestHTTPNeedsToken(t *testing.T) {
	ts := httpEnv(t, newFakeOps(), nil)
	for name, hdr := range map[string]string{"missing": "", "unknown": "Bearer nope", "wrong scheme": "Basic abc"} {
		req, err := http.NewRequestWithContext(ctxT(t), http.MethodPost, ts.URL+Path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, resp.StatusCode)
		}
	}
}

func TestHTTPScopesAndAudit(t *testing.T) {
	ops := newFakeOps()
	aud := &fakeAudit{}
	ts := httpEnv(t, ops, aud)

	// A read-only token: reads work, a mutating call is refused and the refusal is audited.
	cs := httpSession(t, ts, "reader")
	var tl tunnelsOut
	decode(t, call(t, cs, "list_tunnels", map[string]any{}), &tl)
	if len(tl.Tunnels) != 2 {
		t.Fatalf("list_tunnels: %+v", tl)
	}
	res := call(t, cs, "close_tunnel", map[string]any{"id": "t1"})
	if !res.IsError || !strings.Contains(text(res), "admin:tunnels") {
		t.Fatalf("close_tunnel with admin:read only: isError=%v %q", res.IsError, text(res))
	}
	res = call(t, cs, "replay_request", map[string]any{"id": 7})
	if !res.IsError || !strings.Contains(text(res), "admin:traffic") {
		t.Fatalf("replay_request without admin:traffic: %q", text(res))
	}
	if len(ops.closed) != 0 || len(ops.replayed) != 0 {
		t.Fatalf("a refused call reached Ops: %v", ops.closed)
	}

	// A token with admin:tunnels may close tunnels, but not revoke tokens.
	cs = httpSession(t, ts, "tunnels")
	decode(t, call(t, cs, "close_tunnel", map[string]any{"id": "t2"}), &ActionResult{})
	if res := call(t, cs, "revoke_token", map[string]any{"id": "x"}); !res.IsError {
		t.Fatal("revoke_token allowed without admin:tokens")
	}

	got := aud.get()
	want := []struct{ actor, action, target, result string }{
		{"tok_r", "mcp.close_tunnel", "t1", "denied"},
		{"tok_r", "mcp.replay_request", "7", "denied"},
		{"tok_t", "mcp.close_tunnel", "t2", "ok"},
		{"tok_t", "mcp.revoke_token", "x", "denied"},
	}
	if len(got) != len(want) {
		t.Fatalf("audit has %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Actor != w.actor || g.Action != w.action || g.Target != w.target || g.Result != w.result {
			t.Errorf("audit[%d] = %+v, want %+v", i, g, w)
		}
	}
	if len(ops.revoked) != 0 {
		t.Fatalf("revoke reached Ops: %v", ops.revoked)
	}
}

func TestRequireAuthWithoutToken(t *testing.T) {
	cs := connect(t, newServer(t, newFakeOps(), Options{RequireAuth: true}))
	res := call(t, cs, "server_status", map[string]any{})
	if !res.IsError || !strings.Contains(text(res), "unauthorized") {
		t.Fatalf("call without token on an authenticated transport: isError=%v %q", res.IsError, text(res))
	}
}
