// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/traffic"
)

// backendStub implements the two Backend methods LocalOps forwards; the embedded nil interface makes any other call
// panic, which is what the tests want.
type backendStub struct {
	adminapi.Backend
	gotClient string
	gotOpen   adminapi.RemoteOpen
	openErr   error
	replayed  uint64
	replayErr error
}

func (b *backendStub) RequestTunnel(_ context.Context, client string, req adminapi.RemoteOpen) (adminapi.RemoteTunnel, error) {
	b.gotClient, b.gotOpen = client, req
	if b.openErr != nil {
		return adminapi.RemoteTunnel{}, b.openErr
	}
	return adminapi.RemoteTunnel{Name: req.Name, Kind: req.Kind, URL: "https://web-home.example.com"}, nil
}

func (b *backendStub) ReplayRequest(_ context.Context, id uint64) (traffic.Request, error) {
	b.replayed = id
	if b.replayErr != nil {
		return traffic.Request{}, b.replayErr
	}
	return traffic.Request{ID: 70, ReplayOf: id, Method: "POST"}, nil
}

type joinStore struct {
	adminapi.Store
	mu    sync.Mutex
	codes []store.JoinCode
}

func (s *joinStore) CreateJoinCode(_ context.Context, jc *store.JoinCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes = append(s.codes, *jc)
	return nil
}

func tokenCtx(actor string, scopes ...string) context.Context {
	return context.WithValue(context.Background(), callerKey{}, caller{actor: actor, scopes: scopes})
}

func TestLocalOpsRequestTunnel(t *testing.T) {
	be := &backendStub{}
	ops := &LocalOps{Backend: be}

	res, err := ops.RequestTunnel(tokenCtx("tok_a", auth.ScopeAdminRemote),
		RequestTunnelParams{Client: "home", Kind: "http", LocalAddr: "8080", Name: "web", Private: true})
	if err != nil || res.Tunnel.URL != "https://web-home.example.com" {
		t.Fatalf("result %+v, %v", res, err)
	}
	want := adminapi.RemoteOpen{Kind: "http", LocalAddr: "8080", Name: "web", Private: true, RequestedBy: "tok_a"}
	if be.gotClient != "home" || be.gotOpen != want {
		t.Errorf("backend got %q %+v, want %+v", be.gotClient, be.gotOpen, want)
	}

	be.openErr = &adminapi.RemoteError{Code: adminapi.CodeRemoteDisabled, Message: "off"}
	_, err = ops.RequestTunnel(context.Background(), RequestTunnelParams{Client: "home", Kind: "tcp", LocalAddr: "22"})
	var re *adminapi.RemoteError
	if !errors.As(err, &re) || re.Code != adminapi.CodeRemoteDisabled {
		t.Errorf("refusal must keep its code: %v", err)
	}
	if be.gotOpen.RequestedBy != DefaultActor {
		t.Errorf("RequestedBy outside a token call = %q, want %q", be.gotOpen.RequestedBy, DefaultActor)
	}
}

func TestLocalOpsReplayRequest(t *testing.T) {
	be := &backendStub{}
	ops := &LocalOps{Backend: be}
	r, err := ops.ReplayRequest(context.Background(), 7)
	if err != nil || r.ID != 70 || r.ReplayOf != 7 || be.replayed != 7 {
		t.Fatalf("%+v, %v", r, err)
	}
	be.replayErr = &adminapi.ConflictError{Message: "the tunnel is offline"}
	var ce *adminapi.ConflictError
	if _, err := ops.ReplayRequest(context.Background(), 8); !errors.As(err, &ce) {
		t.Errorf("conflict lost: %v", err)
	}
}

func TestLocalOpsCreateJoinLink(t *testing.T) {
	st := &joinStore{}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ops := &LocalOps{Store: st, ServerURL: "https://tun.example.com/", Now: func() time.Time { return now }}

	jl, err := ops.CreateJoinLink(tokenCtx("tok_a", auth.ScopeAdminTokens),
		JoinLinkParams{Client: "laptop", TTL: 30 * time.Minute, AllowRemote: false})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(jl.URL, "https://tun.example.com/j/") || jl.Command != "porthole join "+jl.URL || jl.Client != "laptop" {
		t.Errorf("link %+v", jl)
	}
	if !jl.ExpiresAt.Equal(now.Add(30 * time.Minute)) {
		t.Errorf("expires %v", jl.ExpiresAt)
	}
	if len(st.codes) != 1 {
		t.Fatalf("stored %d codes", len(st.codes))
	}
	jc := st.codes[0]
	if jc.ClientName != "laptop" || jc.RemoteControl || jc.CreatedBy != "tok_a" || len(jc.Scopes) == 0 {
		t.Errorf("stored code %+v", jc)
	}

	// A token may grant only what it holds, as in the admin API; the trusted default caller may grant anything.
	_, err = ops.CreateJoinLink(tokenCtx("tok_a", auth.ScopeAdminTokens), JoinLinkParams{Client: "x1", Scopes: []string{auth.ScopeAdminTraffic}})
	var apiErr *adminapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "forbidden" {
		t.Errorf("escalation: %v", err)
	}
	if _, err := ops.CreateJoinLink(context.Background(), JoinLinkParams{Client: "x2", Scopes: []string{auth.ScopeAdminTraffic}}); err != nil {
		t.Errorf("trusted caller: %v", err)
	}
	if _, err := ops.CreateJoinLink(context.Background(), JoinLinkParams{Client: "Bad Name"}); !errors.As(err, &apiErr) || apiErr.Code != "invalid_request" {
		t.Errorf("invalid name: %v", err)
	}
	if _, err := (&LocalOps{Store: st}).CreateJoinLink(context.Background(), JoinLinkParams{Client: "x3"}); err == nil {
		t.Error("no server URL: want an error")
	}
}

// fakeSocket serves canned answers on a unix socket and records what the admin API client sent.
type fakeSocket struct {
	mu    sync.Mutex
	calls []string // "METHOD path?query"
	body  map[string]any
}

func (f *fakeSocket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, adminapi.Prefix)
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+path+"?"+r.URL.RawQuery)
	if r.Body != nil && r.ContentLength != 0 {
		f.body = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&f.body)
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case r.Method == http.MethodPost && path == "/join":
		reply(adminapi.JoinCreated{
			ID: "j1", Link: "https://tun.example.com/j/CODE", Command: "porthole join https://tun.example.com/j/CODE",
			ClientName: "laptop", ExpiresAt: time.Date(2026, 10, 1, 12, 15, 0, 0, time.UTC),
		})
	case path == "/clients/gone/tunnels":
		w.WriteHeader(http.StatusNotFound)
		reply(map[string]any{"error": map[string]string{"code": "not_found", "message": "client is not connected"}})
	case path == "/clients/home/tunnels":
		reply(map[string]any{"ok": true, "tunnel": adminapi.RemoteTunnel{Name: "web", Kind: "http", URL: "https://web-home.example.com"}})
	case path == "/requests" && r.URL.Query().Get("aggregate") != "":
		reply(map[string]any{"aggregates": traffic.Aggregates{
			Total: 3, StatusClasses: map[string]int{"4xx": 3}, Latency: traffic.Percentiles{P50: 2 * time.Millisecond},
		}})
	case path == "/requests":
		reply(map[string]any{"requests": []traffic.Request{{ID: 7, Path: "/wp-admin", Status: 404, Latency: 1500 * time.Microsecond}}})
	case path == "/requests/7":
		reply(traffic.Request{ID: 7, HasDetail: true, Detail: &traffic.Detail{RequestHeaders: http.Header{"X-Probe": {"1"}}}})
	case path == "/requests/7/replay":
		reply(traffic.Request{ID: 70, ReplayOf: 7})
	case path == "/connections":
		reply(map[string]any{"connections": []traffic.Conn{{ID: 1, Kind: "ssh", Outcome: "limit", Duration: 2 * time.Second}}})
	case path == "/auth-failures":
		reply(map[string]any{"auth_failures": []traffic.Conn{{ID: 2, Kind: "ssh", Outcome: "auth_failed"}}})
	default:
		w.WriteHeader(http.StatusNotFound)
		reply(map[string]any{"error": map[string]string{"code": "not_found", "message": "no route"}})
	}
}

func socketOps(t *testing.T) (SocketOps, *fakeSocket) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets are not available here: %v", err)
	}
	fs := &fakeSocket{}
	srv := httptest.NewUnstartedServer(fs)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return SocketOps{Client: adminapi.NewSocketClient(path)}, fs
}

func TestSocketOps(t *testing.T) {
	ops, fs := socketOps(t)
	ctx := ctxT(t)

	jl, err := ops.CreateJoinLink(ctx, JoinLinkParams{Client: "laptop", Scopes: []string{"tunnel:http"}, TTL: 15 * time.Minute, AllowRemote: false})
	if err != nil || jl.Command != "porthole join https://tun.example.com/j/CODE" || jl.Client != "laptop" || jl.URL == "" || jl.ExpiresAt.IsZero() {
		t.Fatalf("CreateJoinLink: %+v, %v", jl, err)
	}
	if fs.body["client_name"] != "laptop" || fs.body["ttl"] != "15m0s" || fs.body["remote_control"] != false {
		t.Errorf("join request body: %v", fs.body)
	}

	rt, err := ops.RequestTunnel(ctx, RequestTunnelParams{Client: "home", Kind: "http", LocalAddr: "8080", Name: "web"})
	if err != nil || rt.Tunnel.URL != "https://web-home.example.com" {
		t.Fatalf("RequestTunnel: %+v, %v", rt, err)
	}
	if fs.body["kind"] != "http" || fs.body["local_addr"] != "8080" {
		t.Errorf("remote open body: %v", fs.body)
	}
	if _, err := ops.RequestTunnel(ctx, RequestTunnelParams{Client: "gone", Kind: "http", LocalAddr: "1"}); !errors.Is(err, adminapi.ErrNotFound) {
		t.Errorf("offline client: %v", err)
	}

	q, err := ops.QueryRequests(ctx, RequestQuery{Tunnel: "blog", StatusClass: 4, Limit: 10, Aggregate: true, TopN: 5})
	if err != nil || len(q.Requests) != 1 || q.Requests[0].LatencyMS != 1.5 || q.Aggregates == nil || q.Aggregates.Total != 3 || q.Aggregates.LatencyMS.P50 != 2 {
		t.Fatalf("QueryRequests: %+v, %v", q, err)
	}
	if last := fs.calls[len(fs.calls)-1]; !strings.Contains(last, "aggregate=1") || !strings.Contains(last, "top=5") || !strings.Contains(last, "tunnel=blog") {
		t.Errorf("aggregate call: %q", last)
	}

	r, err := ops.GetRequest(ctx, 7)
	if err != nil || r.Detail == nil || r.Detail.RequestHeaders.Get("X-Probe") != "1" || !r.HasDetail {
		t.Fatalf("GetRequest: %+v, %v", r, err)
	}
	rep, err := ops.ReplayRequest(ctx, 7)
	if err != nil || rep.ID != 70 || rep.ReplayOf != 7 {
		t.Fatalf("ReplayRequest: %+v, %v", rep, err)
	}
	cs, err := ops.ConnectionLog(ctx, ConnQuery{Kind: "ssh"})
	if err != nil || len(cs) != 1 || cs[0].DurationMS != 2000 {
		t.Fatalf("ConnectionLog: %+v, %v", cs, err)
	}
	fl, err := ops.GatewayAuthFailures(ctx, time.Time{}, 3)
	if err != nil || len(fl) != 1 || fl[0].Outcome != "auth_failed" {
		t.Fatalf("GatewayAuthFailures: %+v, %v", fl, err)
	}
}
