// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/traffic"
)

func fakeRequest(id uint64) traffic.Request {
	return traffic.Request{
		ID: id, Path: "/p", Status: 200, HasDetail: true,
		Detail: &traffic.Detail{ResponseBody: traffic.Body{Data: []byte("secret body"), Size: 11}},
	}
}

func (f *fakeBackend) Requests(_ context.Context, fl traffic.RequestFilter) ([]traffic.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filter = fl
	return []traffic.Request{fakeRequest(2), fakeRequest(1)}, nil
}

func (f *fakeBackend) RequestAggregates(_ context.Context, fl traffic.RequestFilter, topN int) (traffic.Aggregates, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filter = fl
	return traffic.Aggregates{Total: topN}, nil
}

func (*fakeBackend) Request(_ context.Context, id uint64) (traffic.Request, error) {
	if id != 7 {
		return traffic.Request{}, ErrNotFound
	}
	return fakeRequest(id), nil
}

func (f *fakeBackend) ReplayRequest(_ context.Context, id uint64) (traffic.Request, error) {
	switch id {
	case 7:
		f.mu.Lock()
		f.replayed = append(f.replayed, id)
		f.mu.Unlock()
		r := fakeRequest(70)
		r.ReplayOf = id
		return r, nil
	case 8:
		return traffic.Request{}, &ConflictError{Message: "the tunnel is offline"}
	}
	return traffic.Request{}, ErrNotFound
}

func (*fakeBackend) Connections(_ context.Context, f traffic.ConnFilter) ([]traffic.Conn, error) {
	return []traffic.Conn{{ID: 1, Kind: f.Kind, Outcome: f.Outcome}}, nil
}

func (*fakeBackend) AuthFailures(_ context.Context, _ time.Time, limit int) ([]traffic.Conn, error) {
	return []traffic.Conn{{ID: 3, Outcome: traffic.OutcomeAuthFailed, Duration: time.Duration(limit)}}, nil
}

func TestTrafficListAndAggregate(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}, "n1": {auth.ScopeTunnelHTTP}})
	h := e.api.BearerHandler()

	status, body, _ := e.do(h, "GET", "/requests?tunnel=web&client=home&status_class=5&path_prefix=/api&ip=1.2.3.4&since=10m&limit=5", "ph_r1_secret")
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	if strings.Contains(body, "secret body") || strings.Contains(body, `"detail"`) {
		t.Errorf("list leaked detail: %s", body)
	}
	var list struct {
		Requests []traffic.Request `json:"requests"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil || len(list.Requests) != 2 {
		t.Fatalf("decode: %v %s", err, body)
	}
	f := e.be.filter
	wantSince := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Add(-10 * time.Minute)
	if f.Tunnel != "web" || f.Client != "home" || f.StatusClass != 5 || f.PathPrefix != "/api" || f.IP != "1.2.3.4" || f.Limit != 5 || !f.Since.Equal(wantSince) {
		t.Errorf("filter %+v", f)
	}

	status, body, _ = e.do(h, "GET", "/requests?aggregate=1&top=3", "ph_r1_secret")
	if status != http.StatusOK || !strings.Contains(body, `"aggregates"`) || !strings.Contains(body, `"total":3`) {
		t.Errorf("aggregate: %d %s", status, body)
	}
	for _, bad := range []string{"status_class=9", "limit=x", "since=yesterday", "limit=100000"} {
		if status, body, _ := e.do(h, "GET", "/requests?"+bad, "ph_r1_secret"); status != http.StatusBadRequest || errCode(t, body) != "invalid_request" {
			t.Errorf("%s: %d %s", bad, status, body)
		}
	}
	if status, _, _ := e.do(h, "GET", "/requests", "ph_n1_secret"); status != http.StatusForbidden {
		t.Errorf("token without admin:read: %d", status)
	}
}

func TestTrafficGetRequestDetailScope(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}, "t1": {auth.ScopeAdminRead, auth.ScopeAdminTraffic}})
	bearer, socket := e.api.BearerHandler(), e.api.SocketHandler()

	status, body, _ := e.do(bearer, "GET", "/requests/7", "ph_r1_secret")
	if status != http.StatusOK || strings.Contains(body, "secret body") || !strings.Contains(body, `"has_detail":true`) {
		t.Errorf("admin:read only: %d %s", status, body)
	}
	for name, h := range map[string]struct {
		h      http.Handler
		bearer string
	}{"traffic scope": {bearer, "ph_t1_secret"}, "socket": {socket, ""}} {
		status, body, _ := e.do(h.h, "GET", "/requests/7", h.bearer)
		if status != http.StatusOK || !strings.Contains(body, "secret body") {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
	if status, body, _ := e.do(bearer, "GET", "/requests/99", "ph_t1_secret"); status != http.StatusNotFound || errCode(t, body) != "not_found" {
		t.Errorf("unknown id: %d %s", status, body)
	}
	if status, body, _ := e.do(bearer, "GET", "/requests/abc", "ph_t1_secret"); status != http.StatusBadRequest {
		t.Errorf("bad id: %d %s", status, body)
	}
}

func TestTrafficReplayScopeAndAudit(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}, "t1": {auth.ScopeAdminTraffic}})
	h := e.api.BearerHandler()

	if status, _, _ := e.do(h, "POST", "/requests/7/replay", "ph_r1_secret"); status != http.StatusForbidden {
		t.Errorf("admin:read replay: %d", status)
	}
	if len(e.be.replayed) != 0 {
		t.Fatal("denied replay reached the backend")
	}
	status, body, _ := e.do(h, "POST", "/requests/7/replay", "ph_t1_secret")
	var got traffic.Request
	if status != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || got.ID != 70 || got.ReplayOf != 7 || got.Detail == nil {
		t.Errorf("replay: %d %s", status, body)
	}
	if status, body, _ := e.do(h, "POST", "/requests/8/replay", "ph_t1_secret"); status != http.StatusConflict || errCode(t, body) != "conflict" || !strings.Contains(body, "offline") {
		t.Errorf("conflict: %d %s", status, body)
	}
	if status, body, _ := e.do(h, "POST", "/requests/9/replay", "ph_t1_secret"); status != http.StatusNotFound {
		t.Errorf("unknown: %d %s", status, body)
	}
	var results []string
	for _, a := range e.st.audit {
		if a.Action == "request.replay" {
			results = append(results, a.Target+":"+a.Result)
		}
	}
	if got := strings.Join(results, ","); got != "7:denied,7:ok,8:error: conflict,9:error: not_found" {
		t.Errorf("audit: %s", got)
	}
}

func TestTrafficConnectionsAndAuthFailures(t *testing.T) {
	e := newEnv(t, map[string][]string{"r1": {auth.ScopeAdminRead}})
	h := e.api.BearerHandler()
	status, body, _ := e.do(h, "GET", "/connections?kind=ssh&outcome=ok", "ph_r1_secret")
	if status != http.StatusOK || !strings.Contains(body, `"connections"`) || !strings.Contains(body, `"kind":"ssh"`) {
		t.Errorf("connections: %d %s", status, body)
	}
	status, body, _ = e.do(h, "GET", "/auth-failures?limit=4", "ph_r1_secret")
	if status != http.StatusOK || !strings.Contains(body, `"auth_failures"`) || !strings.Contains(body, `"duration_ns":4`) {
		t.Errorf("auth-failures: %d %s", status, body)
	}
}
