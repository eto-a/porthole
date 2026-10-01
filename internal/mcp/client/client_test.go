// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/eto-a/porthole/internal/localapi"
)

// fakeDaemon is a Daemon that keeps its tunnels in memory; opened tunnels become ready after readyAfter polls.
type fakeDaemon struct {
	mu         sync.Mutex
	tunnels    []localapi.Tunnel
	added      []localapi.AddTunnelRequest
	removed    []string
	readyAfter int
	polls      int
	addErr     error
}

func (f *fakeDaemon) Status(context.Context) (localapi.Status, error) {
	return localapi.Status{Version: "v1", State: localapi.StateConnected, ClientName: "home"}, nil
}

func (f *fakeDaemon) Tunnels(context.Context) ([]localapi.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	if f.polls > f.readyAfter {
		for i := range f.tunnels {
			f.tunnels[i].State = localapi.TunnelReady
			f.tunnels[i].PublicURL = "https://" + f.tunnels[i].Name + ".example.com"
		}
	}
	return slices.Clone(f.tunnels), nil
}

func (f *fakeDaemon) AddTunnel(_ context.Context, req localapi.AddTunnelRequest) (localapi.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return localapi.Tunnel{}, f.addErr
	}
	f.added = append(f.added, req)
	name := req.Name
	if name == "" {
		name = "auto"
	}
	t := localapi.Tunnel{Name: name, Type: req.Type, LocalAddr: req.Addr, State: localapi.TunnelPending, Lifetime: req.Lifetime}
	f.tunnels = append(f.tunnels, t)
	return t, nil
}

func (f *fakeDaemon) RemoveTunnel(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, name)
	return nil
}

func session(t *testing.T, opts Options) *mcp.ClientSession {
	t.Helper()
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
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

func dialer(d Daemon) Dial {
	return func(context.Context) (Daemon, func(), error) { return d, func() {}, nil }
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
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

func TestOpenTunnel(t *testing.T) {
	d := &fakeDaemon{readyAfter: 1}
	cs := session(t, Options{Dial: dialer(d)})

	res := call(t, cs, "open_tunnel", map[string]any{"type": "http", "local_addr": "3000", "name": "blog"})
	if res.IsError {
		t.Fatalf("open_tunnel: %s", text(res))
	}
	var got localapi.Tunnel
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "blog" || got.State != localapi.TunnelReady || got.PublicURL != "https://blog.example.com" {
		t.Fatalf("tunnel: %+v", got)
	}
	want := localapi.AddTunnelRequest{Type: "http", Name: "blog", Addr: "3000", Lifetime: localapi.LifetimeRuntime}
	if len(d.added) != 1 || d.added[0] != want {
		t.Fatalf("daemon got %+v, want %+v", d.added, want)
	}

	if res := call(t, cs, "open_tunnel", map[string]any{"type": "udp", "local_addr": "1"}); !res.IsError {
		t.Fatal("type udp accepted")
	}
	d.addErr = localapi.NewError(localapi.CodeNameTaken, "name %q is taken", "blog")
	if res := call(t, cs, "open_tunnel", map[string]any{"type": "http", "local_addr": "3000", "name": "blog"}); !res.IsError || !strings.Contains(text(res), "taken") {
		t.Fatalf("daemon error: isError=%v %q", res.IsError, text(res))
	}

	res = call(t, cs, "close_tunnel", map[string]any{"name": "blog"})
	if res.IsError || !slices.Equal(d.removed, []string{"blog"}) {
		t.Fatalf("close_tunnel: %v removed=%v", res.IsError, d.removed)
	}
	if res := call(t, cs, "list_tunnels", map[string]any{}); res.IsError {
		t.Fatalf("list_tunnels: %s", text(res))
	}
	if res := call(t, cs, "status", map[string]any{}); res.IsError {
		t.Fatalf("status: %s", text(res))
	}
}

func TestOpenTunnelPendingAtTimeout(t *testing.T) {
	d := &fakeDaemon{readyAfter: 1 << 20}
	cs := session(t, Options{Dial: dialer(d), ReadyTimeout: 300 * time.Millisecond})
	res := call(t, cs, "open_tunnel", map[string]any{"type": "tcp", "local_addr": "5432"})
	if res.IsError || !strings.Contains(string(mustJSON(t, res.StructuredContent)), localapi.TunnelPending) {
		t.Fatalf("want the pending tunnel back: %v %s", res.IsError, mustJSON(t, res.StructuredContent))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadOnly(t *testing.T) {
	cs := session(t, Options{Dial: dialer(&fakeDaemon{}), ReadOnly: true})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"list_tunnels", "status"}) {
		t.Fatalf("tools = %v", names)
	}
}

func TestNoDaemon(t *testing.T) {
	cs := session(t, Options{Dial: func(context.Context) (Daemon, func(), error) {
		return nil, nil, errors.New("no porthole daemon is running")
	}})
	res := call(t, cs, "status", map[string]any{})
	if !res.IsError || !strings.Contains(text(res), "no porthole daemon") {
		t.Fatalf("isError=%v %q", res.IsError, text(res))
	}
}
