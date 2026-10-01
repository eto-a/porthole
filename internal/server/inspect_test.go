// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/traffic"
)

// registerInspect registers a tunnel with Inspect set and returns the reply.
func (c *client) registerInspect(kind, name string) proto.Message {
	c.t.Helper()
	c.reqID++
	if err := c.write(&proto.Register{ReqID: c.reqID, Kind: kind, Name: name, Inspect: true}); err != nil {
		c.t.Fatalf("write register: %v", err)
	}
	return c.next()
}

// inspSeen is what the local service saw.
type inspSeen struct {
	method, uri, auth, cookie, custom, body string
}

// inspBackend answers /big with a large body and everything else with "ok"; it remembers what it was sent.
func inspBackend(t *testing.T, big int) (*httptest.Server, func() []inspSeen) {
	t.Helper()
	var mu sync.Mutex
	var seen []inspSeen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, inspSeen{r.Method, r.RequestURI, r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Header.Get("X-Custom"), string(b)})
		mu.Unlock()
		w.Header().Add("Set-Cookie", "session=backend-secret")
		w.Header().Set("X-Reply", "yes")
		if r.URL.Path == "/big" {
			// Several flushes: the visitor must get the whole body while the journal keeps the first 64 KiB.
			chunk := bytes.Repeat([]byte("b"), 32<<10)
			for n := 0; n < big; n += len(chunk) {
				_, _ = w.Write(chunk)
				w.(http.Flusher).Flush()
			}
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, func() []inspSeen {
		mu.Lock()
		defer mu.Unlock()
		return append([]inspSeen(nil), seen...)
	}
}

// visit sends a visitor request and returns the status and the number of body bytes received.
func (h *harness) visit(host, method, target, body string, hdr map[string]string) (status, n int) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.web.URL+target, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.httpc.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		h.t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, int(got)
}

func TestInspectStoresBodiesAndMasksHeaders(t *testing.T) {
	h := newHarness(t)
	const big = 320 << 10
	backend, _ := inspBackend(t, big)
	c := h.login(h.st.newToken(t, "home"))
	if r, ok := c.registerInspect(proto.KindHTTP, "web").(*proto.Registered); !ok {
		t.Fatalf("register: %#v", r)
	}
	c.serve(forward(backend.Listener.Addr().String()))
	c.mustRegister(proto.KindHTTP, "plain", 0) // an ordinary tunnel of the same client

	reqBody := strings.Repeat("r", 100<<10)
	status, n := h.visit("web-home.example.test", http.MethodPost, "/big?api_key=SECRET&x=1", reqBody,
		map[string]string{"Authorization": "Bearer top-secret", "Cookie": "sid=cookie-secret", "X-Custom": "kept"})
	if status != http.StatusOK || n != big {
		t.Fatalf("visitor got status %d with %d bytes, want 200 with %d", status, n, big)
	}
	h.visit("web-home.example.test", http.MethodGet, "/small", "", nil)
	h.visit("plain-home.example.test", http.MethodPost, "/small", "not stored", nil)

	got := waitRequests(t, h.srv, traffic.RequestFilter{}, 3)
	plain, small, bigReq := got[0], got[1], got[2]
	if plain.Detail != nil || plain.HasDetail {
		t.Errorf("tunnel without inspect kept a detail: %+v", plain)
	}
	full, ok := h.srv.Traffic().Requests().Get(bigReq.ID)
	if !ok || full.Detail == nil {
		t.Fatalf("no detail for the big request: %+v", full)
	}
	d := full.Detail
	if len(d.RequestBody.Data) != traffic.MaxBodyBytes || !d.RequestBody.Truncated || d.RequestBody.Size != int64(len(reqBody)) {
		t.Errorf("request body: %d bytes, truncated %v, size %d", len(d.RequestBody.Data), d.RequestBody.Truncated, d.RequestBody.Size)
	}
	if len(d.ResponseBody.Data) != traffic.MaxBodyBytes || !d.ResponseBody.Truncated || d.ResponseBody.Size != big {
		t.Errorf("response body: %d bytes, truncated %v, size %d", len(d.ResponseBody.Data), d.ResponseBody.Truncated, d.ResponseBody.Size)
	}
	if full.BytesOut != big || full.BytesIn != int64(len(reqBody)) {
		t.Errorf("byte counters %d in, %d out", full.BytesIn, full.BytesOut)
	}
	for name, want := range map[string]string{"Authorization": traffic.Redacted, "Cookie": traffic.Redacted, "X-Custom": "kept"} {
		if v := d.RequestHeaders.Get(name); v != want {
			t.Errorf("request header %s = %q, want %q", name, v, want)
		}
	}
	if v := d.ResponseHeaders.Get("Set-Cookie"); v != traffic.Redacted {
		t.Errorf("Set-Cookie = %q", v)
	}
	if d.ResponseHeaders.Get("X-Reply") != "yes" {
		t.Errorf("response headers: %v", d.ResponseHeaders)
	}
	if full.Query != "api_key=REDACTED&x=1" || d.Target != "/big?api_key=SECRET&x=1" {
		t.Errorf("query %q, target %q", full.Query, d.Target)
	}
	if sd, ok := h.srv.Traffic().Requests().Get(small.ID); !ok || sd.Detail == nil || string(sd.Detail.ResponseBody.Data) != "ok" || sd.Detail.ResponseBody.Truncated {
		t.Errorf("small response: %+v", sd.Detail)
	}
	dump := fmt.Sprintf("%+v", d.RequestHeaders) + fmt.Sprintf("%+v", d.ResponseHeaders)
	for _, secret := range []string{"top-secret", "cookie-secret", "backend-secret"} {
		if strings.Contains(dump, secret) {
			t.Errorf("detail leaked %q", secret)
		}
	}
}

func TestInspectNotForUpgrades(t *testing.T) {
	h := newHarness(t)
	backend, _ := inspBackend(t, 0)
	c := h.login(h.st.newToken(t, "home"))
	c.registerInspect(proto.KindHTTP, "web")
	c.serve(forward(backend.Listener.Addr().String()))
	// Not a real upgrade: the header alone is enough to skip inspection.
	h.visit("web-home.example.test", http.MethodGet, "/ws", "", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"})
	got := waitRequests(t, h.srv, traffic.RequestFilter{}, 1)
	if r, _ := h.srv.Traffic().Requests().Get(got[0].ID); r.Detail != nil {
		t.Errorf("upgrade request was inspected: %+v", r.Detail)
	}
}

func TestInspectRefusals(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Traffic.AllowInspect = false })
	c := h.login(h.st.newToken(t, "home"))
	if e, ok := c.registerInspect(proto.KindHTTP, "web").(*proto.Error); !ok || e.Code != proto.CodeForbidden {
		t.Errorf("allow_inspect=false: %#v", e)
	}
	h2 := newHarness(t)
	c2 := h2.login(h2.st.newToken(t, "home"))
	if e, ok := c2.registerInspect(proto.KindTCP, "db").(*proto.Error); !ok || e.Code != proto.CodeInvalidRequest {
		t.Errorf("inspect on tcp: %#v", e)
	}
}

func TestReplayRequest(t *testing.T) {
	h := newHarness(t)
	backend, seen := inspBackend(t, 0)
	c := h.login(h.st.newToken(t, "home"))
	c.registerInspect(proto.KindHTTP, "web")
	c.serve(forward(backend.Listener.Addr().String()))
	c.mustRegister(proto.KindHTTP, "plain", 0)

	h.visit("web-home.example.test", http.MethodPost, "/api/items?api_key=SECRET&x=1", `{"a":1}`,
		map[string]string{"Authorization": "Bearer top-secret", "Cookie": "sid=1", "X-Custom": "kept", "Content-Type": "application/json"})
	h.visit("plain-home.example.test", http.MethodGet, "/p", "", nil)
	h.visit("web-home.example.test", http.MethodPost, "/big", strings.Repeat("z", 70<<10), nil)
	reqs := waitRequests(t, h.srv, traffic.RequestFilter{}, 3)
	truncated, plain, orig := reqs[0], reqs[1], reqs[2]
	if plain.Path != "/p" || truncated.Path != "/big" || orig.Path != "/api/items" {
		t.Fatalf("unexpected journal: %+v", reqs)
	}
	ctx := context.Background()

	got, err := h.srv.ReplayRequest(ctx, orig.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == orig.ID || got.ReplayOf != orig.ID || got.Status != http.StatusOK || got.Path != "/api/items" || got.Method != http.MethodPost || got.Detail == nil {
		t.Errorf("replay entry: %+v", got)
	}
	if string(got.Detail.RequestBody.Data) != `{"a":1}` || string(got.Detail.ResponseBody.Data) != "ok" {
		t.Errorf("replay detail: %+v", got.Detail)
	}
	calls := seen()
	last := calls[len(calls)-1]
	if len(calls) != 4 || last.method != http.MethodPost || last.uri != "/api/items?api_key=SECRET&x=1" || last.body != `{"a":1}` || last.custom != "kept" {
		t.Errorf("service saw %+v (of %d calls)", last, len(calls))
	}
	if last.auth != "" || last.cookie != "" {
		t.Errorf("redacted headers were sent again: %+v", last)
	}
	if again, err := h.srv.ReplayRequest(ctx, got.ID); err != nil || again.ReplayOf != got.ID {
		t.Errorf("replay of a replay: %+v, %v", again, err)
	}

	refused := func(what string, id uint64, wantText string) {
		t.Helper()
		_, err := h.srv.ReplayRequest(ctx, id)
		if !errors.Is(err, ErrReplayRefused) || !strings.Contains(err.Error(), wantText) {
			t.Errorf("%s: %v, want a refusal mentioning %q", what, err, wantText)
		}
		var ce *adminapi.ConflictError
		if _, err := (adminBackend{h.srv}).ReplayRequest(ctx, id); !errors.As(err, &ce) || !strings.Contains(ce.Message, wantText) || strings.Contains(ce.Message, "server:") {
			t.Errorf("%s via the backend: %v", what, err)
		}
	}
	if _, err := h.srv.ReplayRequest(ctx, 99999); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("unknown id: %v", err)
	}
	refused("not inspected", plain.ID, "not inspected")
	refused("truncated body", truncated.ID, "truncated")

	c.close()
	waitFor(t, "tunnels gone", func() bool { return h.srv.tunnelCount() == 0 })
	refused("offline", orig.ID, "offline")
}

func TestReplayThroughAdminBackendWhenJournalOff(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Traffic.MaxRequests = 0 })
	if _, err := (adminBackend{h.srv}).ReplayRequest(context.Background(), 1); !errors.Is(err, adminapi.ErrNotFound) {
		t.Errorf("journal off: %v", err)
	}
}

func TestInspectDetailBudgetEvictsOldDetails(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Traffic.MaxDetailBytes = 6000 })
	backend, _ := inspBackend(t, 0)
	c := h.login(h.st.newToken(t, "home"))
	c.registerInspect(proto.KindHTTP, "web")
	c.serve(forward(backend.Listener.Addr().String()))
	for i := range 6 {
		h.visit("web-home.example.test", http.MethodPost, fmt.Sprintf("/n/%d", i), strings.Repeat("x", 1500), nil)
		waitRequests(t, h.srv, traffic.RequestFilter{}, i+1)
	}
	reqs := h.srv.Traffic().Requests()
	if b := reqs.DetailBytes(); b > 6000 || b == 0 {
		t.Errorf("detail bytes %d, budget 6000", b)
	}
	list := reqs.Query(traffic.RequestFilter{})
	if len(list) != 6 || !list[0].HasDetail || list[5].HasDetail {
		t.Fatalf("newest must keep its detail and the oldest lose it: %+v", list)
	}
	if _, err := h.srv.ReplayRequest(context.Background(), list[5].ID); !errors.Is(err, ErrReplayRefused) {
		t.Errorf("replay of an evicted detail: %v", err)
	}
}
