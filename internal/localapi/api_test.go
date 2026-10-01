// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

func TestRoutes(t *testing.T) {
	e := newEnv(t)
	ctx := ctxT(t)

	st, err := e.c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != "test" || st.PID != 42 || st.State != StateConnected || st.ClientName != "me" {
		t.Errorf("Status = %+v", st)
	}
	if st.Tunnels == nil {
		t.Error("Status.Tunnels decoded as nil, want empty slice")
	}

	ts, err := e.c.Tunnels(ctx)
	if err != nil || len(ts) != 0 {
		t.Fatalf("Tunnels = %v, %v; want empty", ts, err)
	}
	if body := e.raw(t, http.MethodGet, "/v1/tunnels", nil, nil).body; strings.TrimSpace(body) != "[]" {
		t.Errorf("empty tunnel list body = %q, want []", body)
	}

	added, err := e.c.AddTunnel(ctx, AddTunnelRequest{Type: TypeHTTP, Name: "blog", Addr: "3000", Lifetime: LifetimeAttached})
	if err != nil {
		t.Fatal(err)
	}
	if added.Name != "blog" || added.State != TunnelPending {
		t.Errorf("AddTunnel = %+v", added)
	}
	if e.b.gotReq.Lifetime != LifetimeRuntime {
		t.Errorf("backend saw lifetime %q, want runtime (Client.AddTunnel forces it)", e.b.gotReq.Lifetime)
	}
	if r := e.raw(t, http.MethodPost, "/v1/tunnels", nil, []byte(`{"type":"tcp","addr":"22","lifetime":"runtime"}`)); r.status != http.StatusCreated {
		t.Errorf("runtime POST status = %d, want 201 (%s)", r.status, r.body)
	}

	ts, err = e.c.Tunnels(ctx)
	if err != nil || len(ts) != 2 {
		t.Fatalf("Tunnels = %v, %v; want 2 entries", ts, err)
	}

	if err := e.c.RemoveTunnel(ctx, "blog"); err != nil {
		t.Fatal(err)
	}
	if got := waitRemoved(t, e.b); got != "blog" {
		t.Errorf("removed %q", got)
	}

	res, err := e.c.Reload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Added, []string{"a"}) || res.Removed == nil || res.Changed == nil || res.Unchanged == nil {
		t.Errorf("Reload = %+v; want Added=[a] and non-nil empty slices", res)
	}
	if body := e.raw(t, http.MethodPost, "/v1/reload", nil, nil).body; !strings.Contains(body, `"removed":[]`) {
		t.Errorf("reload body %q lacks removed:[]", body)
	}
}

func TestRemovePathEscaping(t *testing.T) {
	e := newEnv(t)
	if err := e.c.RemoveTunnel(ctxT(t), "a b/c"); err != nil {
		t.Fatal(err)
	}
	if got := waitRemoved(t, e.b); got != "a b/c" {
		t.Errorf("removed %q, want %q", got, "a b/c")
	}
}

func TestSecurityHeadersAndRejections(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"ok", nil, http.StatusOK},
		{"wrong host", map[string]string{"Host": "evil.example"}, http.StatusForbidden},
		{"host with port", map[string]string{"Host": "porthole:80"}, http.StatusForbidden},
		{"localhost", map[string]string{"Host": "localhost"}, http.StatusForbidden},
		{"origin", map[string]string{"Origin": "http://evil.example"}, http.StatusForbidden},
		{"referer", map[string]string{"Referer": "http://evil.example/x"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.raw(t, http.MethodGet, "/v1/status", tc.hdr, nil)
			want := tc.want
			if r.status != want {
				t.Fatalf("status = %d, want %d (%s)", r.status, want, r.body)
			}
			if got := r.header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q", got)
			}
			if want == http.StatusForbidden {
				var body errorBody
				if err := json.Unmarshal([]byte(r.body), &body); err != nil || body.Error == nil || body.Error.Code != CodeForbidden {
					t.Errorf("body = %q, want forbidden error", r.body)
				}
			}
		})
	}
	if calls := e.b.callLog(); len(calls) != 1 {
		t.Errorf("backend calls = %v, want only the one accepted request", calls)
	}
}

func TestBodyCap(t *testing.T) {
	e := newEnv(t)
	big := `{"type":"http","addr":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	r := e.raw(t, http.MethodPost, "/v1/tunnels", nil, []byte(big))
	if r.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (%.100s)", r.status, r.body)
	}
	if slices.Contains(e.b.callLog(), "add") {
		t.Error("backend AddTunnel called for an oversized body")
	}
}

func TestInvalidBodies(t *testing.T) {
	e := newEnv(t)
	cases := map[string]string{
		"unknown field":   `{"type":"http","addr":"3000","bogus":1}`,
		"trailing data":   `{"type":"http","addr":"3000"} {"x":1}`,
		"not json":        `hello`,
		"empty":           ``,
		"bad type":        `{"type":"udp","addr":"3000"}`,
		"missing type":    `{"addr":"3000"}`,
		"bad lifetime":    `{"type":"http","addr":"3000","lifetime":"forever"}`,
		"wrong field typ": `{"type":"http","addr":3000}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := e.raw(t, http.MethodPost, "/v1/tunnels", nil, []byte(body))
			if r.status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", r.status, r.body)
			}
			var b errorBody
			if err := json.Unmarshal([]byte(r.body), &b); err != nil || b.Error == nil || b.Error.Code != CodeInvalidRequest {
				t.Errorf("body = %q, want invalid_request", r.body)
			}
		})
	}
	if slices.Contains(e.b.callLog(), "add") {
		t.Error("backend AddTunnel called for an invalid body")
	}
}

func TestNotFoundAndMethodNotAllowed(t *testing.T) {
	e := newEnv(t)
	r := e.raw(t, http.MethodGet, "/v2/status", nil, nil)
	if r.status != http.StatusNotFound || !strings.Contains(r.body, `"not_found"`) {
		t.Errorf("unknown path: %d %s", r.status, r.body)
	}
	r = e.raw(t, http.MethodPut, "/v1/tunnels", nil, []byte(`{}`))
	if r.status != http.StatusMethodNotAllowed || r.header.Get("Allow") != "GET, POST" || !strings.Contains(r.body, `"invalid_request"`) {
		t.Errorf("PUT /v1/tunnels: %d allow=%q %s", r.status, r.header.Get("Allow"), r.body)
	}
	r = e.raw(t, http.MethodGet, "/v1/reload", nil, nil)
	if r.status != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/reload: %d", r.status)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		code   string
		status int
	}{
		{CodeInvalidRequest, http.StatusBadRequest},
		{CodeForbidden, http.StatusForbidden},
		{CodeNotFound, http.StatusNotFound},
		{CodeNameTaken, http.StatusConflict},
		{CodeConflict, http.StatusConflict},
		{"port_unavailable", http.StatusConflict},
		{"limit_exceeded", http.StatusTooManyRequests},
		{"shutting_down", http.StatusServiceUnavailable},
		{CodeInternal, http.StatusInternalServerError},
		{"something_new", http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			e := newEnv(t)
			e.b.rmErr = NewError(tc.code, "boom %d", 1)
			r := e.raw(t, http.MethodDelete, "/v1/tunnels/x", nil, nil)
			if r.status != tc.status {
				t.Fatalf("HTTP status = %d, want %d", r.status, tc.status)
			}
			// ... and the client turns it back into the same *Error.
			err := e.c.RemoveTunnel(ctxT(t), "x")
			var ae *Error
			if !errors.As(err, &ae) || ae.Code != tc.code || ae.Message != "boom 1" {
				t.Errorf("client error = %v, want *Error{%s, boom 1}", err, tc.code)
			}
			if IsUnavailable(err) || IsPermissionDenied(err) {
				t.Errorf("API error classified as transport error: %v", err)
			}
		})
	}
}

func TestBackendPlainErrorIsInternal(t *testing.T) {
	e := newEnv(t)
	e.b.rmErr = errors.New("secret detail")
	r := e.raw(t, http.MethodDelete, "/v1/tunnels/x", nil, nil)
	if r.status != http.StatusInternalServerError || strings.Contains(r.body, "secret detail") || !strings.Contains(r.body, `"internal"`) {
		t.Errorf("got %d %s", r.status, r.body)
	}
}

func TestWrappedBackendError(t *testing.T) {
	e := newEnv(t)
	e.b.addErr = errors.Join(errors.New("ctx"), NewError(CodeNameTaken, "taken"))
	_, err := e.c.AddTunnel(ctxT(t), AddTunnelRequest{Type: TypeHTTP, Addr: "1"})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != CodeNameTaken {
		t.Errorf("err = %v, want name_taken", err)
	}
}

func TestReloadError(t *testing.T) {
	e := newEnv(t)
	e.b.reloadFn = func() (ReloadResult, error) { return ReloadResult{}, NewError(CodeInvalidRequest, "line 3: bad") }
	_, err := e.c.Reload(ctxT(t))
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != CodeInvalidRequest || ae.Message != "line 3: bad" {
		t.Errorf("err = %v", err)
	}
}

func collect() (func(Event) error, func() []Event) {
	var mu sync.Mutex
	var evs []Event
	return func(ev Event) error {
			mu.Lock()
			evs = append(evs, ev)
			mu.Unlock()
			return nil
		}, func() []Event {
			mu.Lock()
			defer mu.Unlock()
			return append([]Event(nil), evs...)
		}
}

func waitEvents(t *testing.T, get func() []Event, n int) []Event {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if evs := get(); len(evs) >= n {
			return evs
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d events, have %v", n, get())
	return nil
}

func TestAttachStreamAndRemoveOnCancel(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fn, got := collect()
	done := make(chan error, 1)
	go func() {
		done <- e.c.Attach(ctx, AddTunnelRequest{Type: TypeHTTP, Addr: "3000"}, fn)
	}()

	evs := waitEvents(t, got, 1)
	first := evs[0]
	if first.Type != EventAttached || first.Tunnel == nil || first.Tunnel.Name != "http-3000" || first.Name != "http-3000" {
		t.Fatalf("first event = %+v", first)
	}
	if first.Tunnel.Lifetime != LifetimeAttached {
		t.Errorf("tunnel lifetime = %q, want attached", first.Tunnel.Lifetime)
	}

	// Subscribe must happen before Add so that no event is lost.
	if calls := e.b.callLog(); !slices.Equal(calls, []string{"subscribe", "add"}) {
		t.Errorf("backend call order = %v, want [subscribe add]", calls)
	}

	e.b.emit(Event{Type: EventTunnelReady, Name: "other", PublicURL: "https://other"})
	e.b.emit(Event{Type: EventConnected, ClientName: "me"})
	e.b.emit(Event{Type: EventTunnelReady, Name: "http-3000", PublicURL: "https://http-3000-me.example.com"})
	e.b.emit(Event{Type: EventDisconnected, Reason: "lost"})

	evs = waitEvents(t, got, 4)
	var types []string
	for _, ev := range evs[1:] {
		types = append(types, ev.Type+":"+ev.Name)
	}
	want := []string{"connected:", "tunnel_ready:http-3000", "disconnected:"}
	if !slices.Equal(types, want) {
		t.Errorf("events after attach = %v, want %v (events of other tunnels must be filtered out)", types, want)
	}
	if evs[2].PublicURL != "https://http-3000-me.example.com" {
		t.Errorf("tunnel_ready = %+v", evs[2])
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Attach returned %v, want context.Canceled", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Attach did not return after cancel")
	}
	if got := waitRemoved(t, e.b); got != "http-3000" {
		t.Errorf("removed %q, want http-3000", got)
	}
	waitSignal(t, e.b.subDone, "subscription end")
}

func TestAttachStopStream(t *testing.T) {
	e := newEnv(t)
	err := e.c.Attach(ctxT(t), AddTunnelRequest{Type: TypeTCP, Name: "db", Addr: "5432"}, func(ev Event) error {
		if ev.Type == EventAttached {
			return ErrStopStream
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Attach = %v, want nil after ErrStopStream", err)
	}
	if got := waitRemoved(t, e.b); got != "db" {
		t.Errorf("removed %q, want db", got)
	}
	waitSignal(t, e.b.subDone, "subscription end")
}

func TestAttachCallbackError(t *testing.T) {
	e := newEnv(t)
	boom := errors.New("boom")
	err := e.c.Attach(ctxT(t), AddTunnelRequest{Type: TypeTCP, Name: "db", Addr: "5432"}, func(Event) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("Attach = %v, want boom", err)
	}
	waitRemoved(t, e.b)
}

func TestAttachRejected(t *testing.T) {
	e := newEnv(t)
	e.b.addErr = NewError(CodeNameTaken, "name blog is taken")
	called := false
	err := e.c.Attach(ctxT(t), AddTunnelRequest{Type: TypeHTTP, Name: "blog", Addr: "3000"}, func(Event) error {
		called = true
		return nil
	})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != CodeNameTaken {
		t.Fatalf("Attach = %v, want name_taken", err)
	}
	if called {
		t.Error("callback called for a rejected request")
	}
	waitSignal(t, e.b.subDone, "subscription end after rejection")
	select {
	case n := <-e.b.removed:
		t.Errorf("RemoveTunnel(%q) called for a tunnel that was never added", n)
	default:
	}
}

func TestAttachRemoveErrorsAreIgnored(t *testing.T) {
	e := newEnv(t)
	e.b.rmErr = NewError(CodeNotFound, "gone")
	_ = e.c.Attach(ctxT(t), AddTunnelRequest{Type: TypeTCP, Name: "db", Addr: "1"}, func(Event) error { return ErrStopStream })
	waitSignal(t, e.b.subDone, "subscription end")
	// give the handler a moment to run release; the test passes if nothing hangs or panics and goleak is happy.
	time.Sleep(50 * time.Millisecond)
	if !slices.Contains(e.b.callLog(), "remove db") {
		t.Errorf("calls = %v, want remove db", e.b.callLog())
	}
}

func TestEventsStream(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn, got := collect()
	done := make(chan error, 1)
	go func() { done <- e.c.Events(ctx, fn) }()
	waitSignal(t, e.b.subCh, "subscription")

	now := time.Now().UTC().Truncate(time.Millisecond)
	in := []Event{
		{Type: EventConnected, ClientName: "me", Time: now},
		{Type: EventTunnelReady, Name: "a", PublicURL: "https://a", Time: now},
		{Type: EventTunnelClosed, Name: "a", Reason: "server", Error: "gone", Time: now},
		{Type: EventDisconnected, Reason: "net", RetryInMS: 1500, Time: now},
	}
	for _, ev := range in {
		e.b.emit(ev)
	}
	evs := waitEvents(t, got, len(in))
	for i := range in {
		if evs[i].Type != in[i].Type || evs[i].Name != in[i].Name || evs[i].PublicURL != in[i].PublicURL ||
			evs[i].Reason != in[i].Reason || evs[i].Error != in[i].Error || evs[i].RetryInMS != in[i].RetryInMS ||
			evs[i].ClientName != in[i].ClientName || !evs[i].Time.Equal(now) {
			t.Errorf("event %d = %+v, want %+v", i, evs[i], in[i])
		}
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Events returned %v, want context.Canceled", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Events did not return after cancel")
	}
	waitSignal(t, e.b.subDone, "subscription end")
}

func TestEventsEndsWhenServerShutsDown(t *testing.T) {
	b := newFakeBackend()
	sock := shortDir(t) + "/p.sock"
	ln, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, ln, NewHandler(b, nil), nil) }()

	c := NewClient(sock)
	defer c.Close()
	evDone := make(chan error, 1)
	go func() { evDone <- c.Events(context.Background(), func(Event) error { return nil }) }()
	waitSignal(t, b.subCh, "subscription")

	stop()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Serve did not return while an event stream was open")
	}
	select {
	case err := <-evDone:
		if err != nil {
			t.Errorf("Events = %v, want nil (stream ended by the server)", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Events did not end after shutdown")
	}
}

func TestStatusUnavailableWhenNoDaemon(t *testing.T) {
	c := NewClient(shortDir(t) + "/nope.sock")
	defer c.Close()
	_, err := c.Status(ctxT(t))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsUnavailable(err) {
		t.Errorf("IsUnavailable(%v) = false, want true", err)
	}
	if IsPermissionDenied(err) {
		t.Errorf("IsPermissionDenied(%v) = true, want false", err)
	}
	if IsUnavailable(nil) || IsPermissionDenied(nil) {
		t.Error("nil error classified")
	}
}
