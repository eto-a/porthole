// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, leakOptions()...)
}

const testTimeout = 5 * time.Second

// shortDir returns a fresh directory with a short path: socket paths are limited to about 104 bytes, and t.TempDir
// includes the test name.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeBackend is a Backend that records calls and lets tests inject results and events.
type fakeBackend struct {
	mu       sync.Mutex
	calls    []string
	tunnels  map[string]Tunnel
	removed  chan string
	subs     map[int]chan Event
	nextSub  int
	subCh    chan struct{} // signalled once per Subscribe
	subDone  chan struct{} // signalled once per finished subscription
	addErr   error
	rmErr    error
	reloadFn func() (ReloadResult, error)
	status   Status
	gotReq   AddTunnelRequest
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		tunnels: map[string]Tunnel{},
		removed: make(chan string, 16),
		subs:    map[int]chan Event{},
		subCh:   make(chan struct{}, 16),
		subDone: make(chan struct{}, 16),
		status:  Status{Version: "test", PID: 42, State: StateConnected, Server: "https://tun.example.com", ClientName: "me"},
	}
}

func (f *fakeBackend) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeBackend) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeBackend) Status(context.Context) Status {
	f.record("status")
	return f.status
}

func (f *fakeBackend) Tunnels(context.Context) []Tunnel {
	f.record("tunnels")
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Collect(maps.Values(f.tunnels))
}

func (f *fakeBackend) AddTunnel(_ context.Context, req AddTunnelRequest) (Tunnel, error) {
	f.record("add")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotReq = req
	if f.addErr != nil {
		return Tunnel{}, f.addErr
	}
	name := req.Name
	if name == "" {
		name = req.Type + "-" + req.Addr
	}
	t := Tunnel{
		Name: name, Type: req.Type, LocalAddr: req.Addr, RemotePort: req.RemotePort,
		State: TunnelPending, Source: SourceRuntime, Lifetime: req.Lifetime,
	}
	f.tunnels[name] = t
	return t, nil
}

func (f *fakeBackend) RemoveTunnel(_ context.Context, name string) error {
	f.record("remove " + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rmErr != nil {
		return f.rmErr
	}
	delete(f.tunnels, name)
	f.removed <- name
	return nil
}

func (f *fakeBackend) Reload(context.Context) (ReloadResult, error) {
	f.record("reload")
	if f.reloadFn != nil {
		return f.reloadFn()
	}
	return ReloadResult{Added: []string{"a"}}, nil
}

func (f *fakeBackend) Subscribe(ctx context.Context) <-chan Event {
	f.record("subscribe")
	ch := make(chan Event, 16)
	f.mu.Lock()
	id := f.nextSub
	f.nextSub++
	f.subs[id] = ch
	f.mu.Unlock()
	f.subCh <- struct{}{}
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		delete(f.subs, id)
		f.mu.Unlock()
		close(ch)
		f.subDone <- struct{}{}
	}()
	return ch
}

// emit delivers ev to every subscriber without blocking.
func (f *fakeBackend) emit(ev Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ch := range f.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func waitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(testTimeout):
		t.Fatalf("timeout waiting for %s", what)
	}
}

func waitRemoved(t *testing.T, f *fakeBackend) string {
	t.Helper()
	select {
	case n := <-f.removed:
		return n
	case <-time.After(testTimeout):
		t.Fatal("timeout waiting for RemoveTunnel")
		return ""
	}
}

// env is a running daemon-side API plus a client for it.
type env struct {
	sock string
	b    *fakeBackend
	c    *Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	b := newFakeBackend()
	sock := filepath.Join(shortDir(t), "p.sock")
	ln, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, NewHandler(b, log), log) }()
	c := NewClient(sock)
	t.Cleanup(func() {
		c.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(testTimeout):
			t.Error("Serve did not return after cancel")
		}
	})
	return &env{sock: sock, b: b, c: c}
}

type rawResp struct {
	status int
	header http.Header
	body   string
}

// raw sends a hand-made request, bypassing Client, so that headers and bodies can be tampered with.
func (e *env) raw(t *testing.T, method, path string, hdr map[string]string, body []byte) rawResp {
	t.Helper()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", e.sock)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+Host+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return rawResp{status: resp.StatusCode, header: resp.Header, body: string(data)}
}
