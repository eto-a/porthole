// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/traffic"
)

type fakeBackend struct {
	mu            sync.Mutex
	disconnected  []string
	closed        []string
	filter        traffic.RequestFilter // the last filter Requests or RequestAggregates saw
	replayed      []uint64
	opened        []RemoteOpen
	revokedTokens []string
}

func (f *fakeBackend) TokenRevoked(_ context.Context, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokedTokens = append(f.revokedTokens, id)
}

func (*fakeBackend) Status(context.Context) (Status, error) {
	return Status{Version: "v-test", Clients: 2, Tunnels: 3, UptimeSeconds: 7}, nil
}

func (*fakeBackend) Clients(context.Context) ([]Client, error) {
	return []Client{{Name: "home", SessionID: "s1", TokenID: "t1", Tunnels: 1}}, nil
}

func (f *fakeBackend) Disconnect(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name != "home" {
		return ErrNotFound
	}
	f.disconnected = append(f.disconnected, name)
	return nil
}

func (*fakeBackend) Tunnels(context.Context) ([]Tunnel, error) { return nil, nil }

func (f *fakeBackend) CloseTunnel(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id != "tun1" {
		return ErrNotFound
	}
	f.closed = append(f.closed, id)
	return nil
}

type fakeStore struct {
	mu      sync.Mutex
	tokens  map[string]*store.Token
	revoked []string
	audit   []store.AuditEntry
	joins   []*store.JoinCode
}

func (f *fakeStore) GetToken(_ context.Context, id string) (*store.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.tokens[id]; ok {
		return t, nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) ListTokens(context.Context) ([]*store.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*store.Token
	for _, t := range f.tokens {
		out = append(out, t)
	}
	return out, nil
}

func (f *fakeStore) RevokeToken(_ context.Context, id string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, id)
	return nil
}

func (f *fakeStore) AppendAudit(_ context.Context, e *store.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audit = append(f.audit, *e)
	return nil
}

func (f *fakeStore) ListAudit(_ context.Context, limit int) ([]store.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]store.AuditEntry(nil), f.audit...)
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func (f *fakeStore) ListAuditBefore(_ context.Context, before int64, limit int) ([]store.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.AuditEntry
	for i := len(f.audit) - 1; i >= 0 && len(out) < limit; i-- {
		if before <= 0 || f.audit[i].ID < before {
			out = append(out, f.audit[i])
		}
	}
	return out, nil
}

func auditFixture(i int) store.AuditEntry {
	return store.AuditEntry{ID: int64(i + 1), Actor: "socket", Action: "a", Result: "ok"}
}

type env struct {
	be  *fakeBackend
	st  *fakeStore
	api *API
}

// newEnv builds an API whose tokens are "ph_<id>_secret" with the scopes listed in tokens (by id).
func newEnv(t *testing.T, tokens map[string][]string) *env {
	t.Helper()
	e := &env{be: &fakeBackend{}, st: &fakeStore{tokens: map[string]*store.Token{}}}
	for id, scopes := range tokens {
		e.st.tokens[id] = &store.Token{ID: id, Name: "n-" + id, Last4: "abcd", Scopes: scopes, SecretHash: []byte("hash-must-not-leak")}
	}
	api, err := New(Options{
		Backend: e.be,
		Store:   e.st,
		Authenticate: func(_ context.Context, ip, raw string) (*store.Token, error) {
			if ip == "9.9.9.9" {
				return nil, &RateLimitedError{RetryAfter: 1500 * time.Millisecond}
			}
			id, ok := strings.CutSuffix(strings.TrimPrefix(raw, "ph_"), "_secret")
			if tok := e.st.tokens[id]; ok && tok != nil {
				return tok, nil
			}
			return nil, ErrUnauthorized
		},
		Now: func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.api = api
	return e
}

func (e *env) do(h http.Handler, method, path, bearer string) (int, string, http.Header) {
	req := httptest.NewRequest(method, Prefix+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

func errCode(t *testing.T, body string) string {
	t.Helper()
	var eb ErrorBody
	if err := json.Unmarshal([]byte(body), &eb); err != nil || eb.Error.Code == "" {
		t.Fatalf("not an error body: %q (%v)", body, err)
	}
	return eb.Error.Code
}

func TestBearerAuthentication(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}})
	h := e.api.BearerHandler()

	status, body, hdr := e.do(h, "GET", "/status", "")
	if status != http.StatusUnauthorized || errCode(t, body) != "unauthorized" || hdr.Get("WWW-Authenticate") == "" {
		t.Errorf("no token: %d %s %v", status, body, hdr)
	}
	if status, body, _ := e.do(h, "GET", "/status", "ph_nope_secret"); status != http.StatusUnauthorized || errCode(t, body) != "unauthorized" {
		t.Errorf("unknown token: %d %s", status, body)
	}
	req := httptest.NewRequest(http.MethodGet, Prefix+"/status", nil)
	req.Header.Set("Authorization", "Basic abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("non-bearer scheme: %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, Prefix+"/status", nil)
	req.Header.Set("Authorization", "Bearer ph_r1_secret")
	req.RemoteAddr = "9.9.9.9:1234"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Errorf("rate limit: %d retry-after %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestReadScope(t *testing.T) {
	e := newEnv(t, map[string][]string{
		"r1": {auth.ScopeAdminRead},
		"c1": {auth.ScopeAdminClients}, // a mutating scope does not imply reading
	})
	h := e.api.BearerHandler()
	for _, p := range []string{"/status", "/clients", "/tunnels", "/tokens", "/audit"} {
		status, body, _ := e.do(h, "GET", p, "ph_r1_secret")
		if status != http.StatusOK {
			t.Errorf("GET %s with admin:read: %d %s", p, status, body)
		}
		status, body, _ = e.do(h, "GET", p, "ph_c1_secret")
		if status != http.StatusForbidden || errCode(t, body) != "forbidden" {
			t.Errorf("GET %s without admin:read: %d %s", p, status, body)
		}
	}
	// Empty lists are [] and not null.
	if _, body, _ := e.do(h, "GET", "/tunnels", "ph_r1_secret"); !strings.Contains(body, `"tunnels":[]`) {
		t.Errorf("tunnels body %q", body)
	}
	var st Status
	_, body, _ := e.do(h, "GET", "/status", "ph_r1_secret")
	if err := json.Unmarshal([]byte(body), &st); err != nil || st.Version != "v-test" || st.Clients != 2 || st.Tunnels != 3 {
		t.Errorf("status %+v (%v)", st, err)
	}
}

func TestReadOnlyTokenCannotMutate(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}})
	h := e.api.BearerHandler()
	for _, c := range []struct{ method, path string }{
		{"POST", "/clients/home/disconnect"},
		{"DELETE", "/tunnels/tun1"},
		{"POST", "/tokens/r1/revoke"},
	} {
		status, body, _ := e.do(h, c.method, c.path, "ph_r1_secret")
		if status != http.StatusForbidden || errCode(t, body) != "forbidden" {
			t.Errorf("%s %s: %d %s", c.method, c.path, status, body)
		}
	}
	if len(e.be.disconnected)+len(e.be.closed)+len(e.st.revoked) != 0 {
		t.Fatal("a denied call reached the backend")
	}
	if len(e.st.audit) != 3 {
		t.Fatalf("denied attempts must be audited: %+v", e.st.audit)
	}
	for _, a := range e.st.audit {
		if a.Result != "denied" || a.Actor != "r1" {
			t.Errorf("audit entry %+v", a)
		}
	}
}

func TestMutationsPerScope(t *testing.T) {
	e := newEnv(t, map[string][]string{
		"cl": {auth.ScopeAdminClients},
		"tu": {auth.ScopeAdminTunnels},
		"tk": {auth.ScopeAdminTokens},
	})
	h := e.api.BearerHandler()

	cases := []struct {
		name, method, path, bearer, action, target string
		wantStatus                                 int
	}{
		{"disconnect ok", "POST", "/clients/home/disconnect", "ph_cl_secret", "client.disconnect", "home", 200},
		{"disconnect unknown", "POST", "/clients/ghost/disconnect", "ph_cl_secret", "client.disconnect", "ghost", 404},
		{"disconnect with tunnels scope", "POST", "/clients/home/disconnect", "ph_tu_secret", "client.disconnect", "home", 403},
		{"close ok", "DELETE", "/tunnels/tun1", "ph_tu_secret", "tunnel.close", "tun1", 200},
		{"close unknown", "DELETE", "/tunnels/nope", "ph_tu_secret", "tunnel.close", "nope", 404},
		{"close with tokens scope", "DELETE", "/tunnels/tun1", "ph_tk_secret", "tunnel.close", "tun1", 403},
		{"revoke ok", "POST", "/tokens/cl/revoke", "ph_tk_secret", "token.revoke", "cl", 200},
		{"revoke unknown", "POST", "/tokens/zzz/revoke", "ph_tk_secret", "token.revoke", "zzz", 404},
		{"revoke with clients scope", "POST", "/tokens/cl/revoke", "ph_cl_secret", "token.revoke", "cl", 403},
	}
	results := []string{"ok", "error: not_found", "denied", "ok", "error: not_found", "denied", "ok", "error: not_found", "denied"}
	for i, c := range cases {
		status, body, _ := e.do(h, c.method, c.path, c.bearer)
		if status != c.wantStatus {
			t.Errorf("%s: status %d, body %s", c.name, status, body)
		}
		if status != http.StatusOK {
			errCode(t, body)
		}
		got := e.st.audit[i]
		if got.Action != c.action || got.Target != c.target || got.Result != results[i] || !got.At.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("%s: audit %+v", c.name, got)
		}
	}
	if len(e.be.disconnected) != 1 || len(e.be.closed) != 1 || len(e.st.revoked) != 1 || e.st.revoked[0] != "cl" {
		t.Errorf("backend calls: %v %v %v", e.be.disconnected, e.be.closed, e.st.revoked)
	}
}

func TestAuditArgsHoldNoSecrets(t *testing.T) {
	e := newEnv(t, map[string][]string{"cl": {auth.ScopeAdminClients}})
	e.do(e.api.BearerHandler(), "POST", "/clients/home/disconnect", "ph_cl_secret")
	a := e.st.audit[0]
	if strings.Contains(a.Args, "secret") || strings.Contains(a.Args, "ph_") || !strings.Contains(a.Args, "remote") {
		t.Errorf("args %q", a.Args)
	}
}

func TestTokensListHidesSecrets(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}})
	_, body, _ := e.do(e.api.BearerHandler(), "GET", "/tokens", "ph_r1_secret")
	if strings.Contains(body, "hash") || strings.Contains(body, "secret") {
		t.Fatalf("secret material in %s", body)
	}
	var out struct {
		Tokens []Token `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Tokens) != 1 || out.Tokens[0].ID != "r1" || out.Tokens[0].Last4 != "abcd" {
		t.Fatalf("tokens %s (%v)", body, err)
	}
}

func TestAuditEndpoint(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}, "cl": {auth.ScopeAdminClients}})
	h := e.api.BearerHandler()
	e.do(h, "POST", "/clients/home/disconnect", "ph_cl_secret")
	e.do(h, "POST", "/clients/home/disconnect", "ph_cl_secret")

	_, body, _ := e.do(h, "GET", "/audit?limit=1", "ph_r1_secret")
	var out struct {
		Entries []AuditEntry `json:"entries"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Entries) != 1 || out.Entries[0].Action != "client.disconnect" || out.Entries[0].Actor != "cl" {
		t.Errorf("audit %s (%v)", body, err)
	}
	for _, bad := range []string{"abc", "0", "-3"} {
		if status, body, _ := e.do(h, "GET", "/audit?limit="+bad, "ph_r1_secret"); status != http.StatusBadRequest || errCode(t, body) != "invalid_request" {
			t.Errorf("limit=%s: %d %s", bad, status, body)
		}
	}
}

func TestSocketHandlerIsTrusted(t *testing.T) {
	e := newEnv(t, nil)
	h := e.api.SocketHandler()
	if status, body, _ := e.do(h, "GET", "/status", ""); status != http.StatusOK {
		t.Fatalf("status without a token: %d %s", status, body)
	}
	if status, body, _ := e.do(h, "DELETE", "/tunnels/tun1", ""); status != http.StatusOK {
		t.Fatalf("close without a token: %d %s", status, body)
	}
	if len(e.st.audit) != 1 || e.st.audit[0].Actor != ActorSocket || e.st.audit[0].Args != "{}" || e.st.audit[0].Result != "ok" {
		t.Errorf("audit %+v", e.st.audit)
	}
}

func TestUnknownEndpoint(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}})
	status, body, _ := e.do(e.api.BearerHandler(), "GET", "/nothing", "ph_r1_secret")
	if status != http.StatusNotFound || errCode(t, body) != "not_found" {
		t.Errorf("%d %s", status, body)
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without dependencies succeeded")
	}
}

func (f *fakeStore) CreateJoinCode(_ context.Context, jc *store.JoinCode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.Name == jc.ClientName {
			return store.ErrNameTaken
		}
	}
	c := *jc
	f.joins = append(f.joins, &c)
	return nil
}

func (f *fakeStore) ListJoinCodes(context.Context) ([]*store.JoinCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*store.JoinCode(nil), f.joins...), nil
}

func (f *fakeStore) RevokeJoinCode(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, j := range f.joins {
		if j.ID == id {
			j.RevokedAt = &at
			return nil
		}
	}
	return store.ErrNotFound
}
