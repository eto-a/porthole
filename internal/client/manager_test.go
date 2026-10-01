// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/proto"
)

// mgrHarness runs a Manager against a fake server.
type mgrHarness struct {
	t        *testing.T
	m        *Manager
	events   <-chan Event
	unsub    func()
	cancel   context.CancelFunc
	finished chan struct{}
	err      error // result of Run, valid after finished is closed
}

// newMgr creates a Manager (not started) and subscribes to its events.
func newMgr(t *testing.T, fs *fakeServer, specs []TunnelSpec, tun tuning, mut ...func(*Options)) *mgrHarness {
	t.Helper()
	fs.expectRegs = -1 // the "ready" channel of the fake server is not used with a Manager
	opts := Options{
		ServerURL: fs.url(),
		Token:     newToken(t),
		Tunnels:   specs,
		Version:   "test",
		Logger:    slog.New(slog.DiscardHandler),
	}
	for _, f := range mut {
		f(&opts)
	}
	return newMgrOpts(t, opts, tun)
}

func newMgrOpts(t *testing.T, opts Options, tun tuning) *mgrHarness {
	t.Helper()
	m, err := newManager(opts, tun, false)
	if err != nil {
		t.Fatal(err)
	}
	h := &mgrHarness{t: t, m: m, finished: make(chan struct{})}
	h.events, h.unsub = m.Subscribe(4096)
	return h
}

// start runs the Manager in a goroutine; the test cleanup stops it.
func (h *mgrHarness) start() *mgrHarness {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		h.err = h.m.Run(ctx)
		close(h.finished)
	}()
	h.t.Cleanup(func() {
		cancel()
		select {
		case <-h.finished:
		case <-time.After(waitFor):
			h.t.Error("Manager.Run did not return after cancel")
		}
	})
	return h
}

func startMgr(t *testing.T, fs *fakeServer, specs []TunnelSpec, tun tuning, mut ...func(*Options)) *mgrHarness {
	t.Helper()
	return newMgr(t, fs, specs, tun, mut...).start()
}

// result waits for Run to return and gives its result.
func (h *mgrHarness) result() error {
	h.t.Helper()
	select {
	case <-h.finished:
		return h.err
	case <-time.After(waitFor):
		h.t.Fatal("Manager.Run did not return")
		return nil
	}
}

func (h *mgrHarness) running() bool {
	select {
	case <-h.finished:
		return false
	default:
		return true
	}
}

// nextEv returns the next event of the wanted type; events of other types are skipped.
func nextEv[T Event](t *testing.T, h *mgrHarness) T {
	t.Helper()
	deadline := time.After(waitFor)
	for {
		select {
		case e, ok := <-h.events:
			if !ok {
				var zero T
				t.Fatalf("event channel closed while waiting for %T", zero)
			}
			if v, ok := e.(T); ok {
				return v
			}
		case <-deadline:
			var zero T
			t.Fatalf("timed out waiting for %T", zero)
		}
	}
}

// noEv fails if an event of type T arrives within d.
func noEv[T Event](t *testing.T, h *mgrHarness, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case e, ok := <-h.events:
			if !ok {
				return
			}
			if v, ok := e.(T); ok {
				t.Fatalf("unexpected event %T: %+v", v, v)
			}
		case <-deadline:
			return
		}
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func tunnelOf(m *Manager, name string) (TunnelState, bool) {
	tunnels := m.Snapshot().Tunnels
	for i := range tunnels {
		if tunnels[i].Spec.Name == name {
			return tunnels[i], true
		}
	}
	return TunnelState{}, false
}

func names(st State) []string {
	out := make([]string, 0, len(st.Tunnels))
	for i := range st.Tunnels {
		out = append(out, st.Tunnels[i].Spec.Name)
	}
	return out
}

// waitStatus waits until the named tunnel has the given status.
func waitStatus(t *testing.T, m *Manager, name string, want TunnelStatus) TunnelState {
	t.Helper()
	var got TunnelState
	eventually(t, fmt.Sprintf("tunnel %q to be %s", name, want), func() bool {
		ts, ok := tunnelOf(m, name)
		got = ts
		return ok && ts.Status == want
	})
	return got
}

func httpSpec(name string, port int) TunnelSpec {
	return TunnelSpec{Kind: proto.KindHTTP, Name: name, LocalAddr: fmt.Sprintf("127.0.0.1:%d", port)}
}

func tcpSpec(name, addr string) TunnelSpec {
	return TunnelSpec{Kind: proto.KindTCP, Name: name, LocalAddr: addr}
}

// countingUpper is upperServer that counts the connections it accepted.
func countingUpper(t *testing.T) (addr string, hits *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits = new(atomic.Int32)
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			wg.Go(func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				data, _ := io.ReadAll(c)
				_, _ = c.Write(bytes.ToUpper(data))
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			})
		}
	})
	return ln.Addr().String(), hits
}

func TestManagerSnapshotBeforeRun(t *testing.T) {
	fs := newFakeServer(t)
	h := newMgr(t, fs, []TunnelSpec{httpSpec("b", 8081), httpSpec("a", 8080)}, testTuning())
	st := h.m.Snapshot()
	if st.Conn != ConnIdle || !st.RetryAt.IsZero() || st.LastErr != nil || st.ClientName != "" {
		t.Fatalf("unexpected state %+v", st)
	}
	if got := names(st); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("tunnels %v are not sorted by name", got)
	}
	for _, ts := range st.Tunnels {
		if ts.Status != StatusPending || ts.PublicURL != "" || ts.Err != nil {
			t.Fatalf("unexpected tunnel state %+v", ts)
		}
	}
}

func TestManagerNewValidation(t *testing.T) {
	good := Options{ServerURL: "http://127.0.0.1:1", Token: newToken(t)}
	if _, err := NewManager(good); err != nil {
		t.Fatalf("an empty tunnel set must be accepted: %v", err)
	}
	cases := map[string]func(*Options){
		"bad url":   func(o *Options) { o.ServerURL = "ftp://x" },
		"bad token": func(o *Options) { o.Token = "nope" },
		"bad kind":  func(o *Options) { o.Tunnels = []TunnelSpec{{Kind: "udp", LocalAddr: "127.0.0.1:1"}} },
		"duplicate": func(o *Options) {
			o.Tunnels = []TunnelSpec{{Kind: "tcp", LocalAddr: "h:80"}, {Kind: "tcp", LocalAddr: "h:80"}}
		},
	}
	for name, mut := range cases {
		o := good
		mut(&o)
		if _, err := NewManager(o); err == nil {
			t.Errorf("%s: NewManager returned nil error", name)
		}
	}
}

func TestManagerEmptySetStaysConnected(t *testing.T) {
	fs := newFakeServer(t)
	h := startMgr(t, fs, nil, testTuning())
	if c := nextEv[Connected](t, h); c.ClientName != "home" {
		t.Fatalf("client name %q", c.ClientName)
	}
	noEv[Disconnected](t, h, 150*time.Millisecond)
	st := h.m.Snapshot()
	if st.Conn != ConnConnected || st.ClientName != "home" || len(st.Tunnels) != 0 || st.LastErr != nil {
		t.Fatalf("unexpected state %+v", st)
	}
	if n := fs.connCount(); n != 1 {
		t.Fatalf("server saw %d connections", n)
	}
}

func TestManagerAddAfterConnect(t *testing.T) {
	fs := newFakeServer(t)
	h := startMgr(t, fs, nil, testTuning())
	nextEv[Connected](t, h)

	sp, err := h.m.Add(TunnelSpec{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if sp.Name != "http-8080" {
		t.Fatalf("default name not applied: %+v", sp)
	}
	if a := nextEv[TunnelAdded](t, h); a.Spec != sp {
		t.Fatalf("TunnelAdded %+v", a)
	}
	r := nextEv[TunnelReady](t, h)
	if r.Name != "http-8080" || r.Spec != sp || r.PublicURL != "https://http-8080-home.tun.test" {
		t.Fatalf("TunnelReady %+v", r)
	}
	ts, ok := tunnelOf(h.m, "http-8080")
	if !ok || ts.Status != StatusReady || ts.PublicURL != r.PublicURL || ts.Err != nil || ts.Spec != sp {
		t.Fatalf("unexpected tunnel state %+v", ts)
	}
	if regs := fs.conn(1).registrations(); len(regs) != 1 || regs[0].Name != "http-8080" {
		t.Fatalf("registrations %+v", regs)
	}
}

func TestManagerAddBeforeConnect(t *testing.T) {
	fs := newFakeServer(t)
	h := newMgr(t, fs, []TunnelSpec{httpSpec("first", 8080)}, testTuning())
	if _, err := h.m.Add(httpSpec("second", 8081)); err != nil {
		t.Fatal(err)
	}
	if got := names(h.m.Snapshot()); !slices.Equal(got, []string{"first", "second"}) {
		t.Fatalf("tunnels %v", got)
	}
	h.start()
	if r := nextEv[TunnelReady](t, h); r.Name != "first" {
		t.Fatalf("first ready tunnel: %+v", r)
	}
	if r := nextEv[TunnelReady](t, h); r.Name != "second" {
		t.Fatalf("second ready tunnel: %+v", r)
	}
	regs := fs.conn(1).registrations()
	if len(regs) != 2 || regs[0].Name != "first" || regs[1].Name != "second" {
		t.Fatalf("registrations must follow insertion order: %+v", regs)
	}
}

func TestManagerAddValidation(t *testing.T) {
	fs := newFakeServer(t)
	h := newMgr(t, fs, []TunnelSpec{httpSpec("web", 8080)}, testTuning())
	if _, err := h.m.Add(httpSpec("web", 9090)); !errors.Is(err, ErrTunnelExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := h.m.Add(TunnelSpec{Kind: "udp", LocalAddr: "127.0.0.1:1"}); err == nil {
		t.Fatal("invalid kind accepted")
	}
	if _, err := h.m.Add(TunnelSpec{Kind: proto.KindHTTP, Name: "Bad_Name", LocalAddr: "127.0.0.1:1"}); err == nil {
		t.Fatal("invalid name accepted")
	}
	if got := names(h.m.Snapshot()); !slices.Equal(got, []string{"web"}) {
		t.Fatalf("failed Adds changed the set: %v", got)
	}
	if err := h.m.Remove("nope"); !errors.Is(err, ErrTunnelNotFound) {
		t.Fatalf("Remove of an unknown tunnel: %v", err)
	}
}

func TestManagerRemoveUnregisters(t *testing.T) {
	local, hits := countingUpper(t)
	fs := newFakeServer(t)
	h := startMgr(t, fs, nil, testTuning())
	nextEv[Connected](t, h)
	if _, err := h.m.Add(tcpSpec("up", local)); err != nil {
		t.Fatal(err)
	}
	nextEv[TunnelReady](t, h)
	c := fs.conn(1)
	id := c.tunnelID("up")

	// a stream that is in flight when the tunnel is removed must be able to finish
	st1 := c.openStream(t, "up")
	defer st1.Close()
	_ = st1.SetDeadline(time.Now().Add(waitFor))
	eventually(t, "the first stream to reach the local target", func() bool { return hits.Load() == 1 })

	if err := h.m.Remove("up"); err != nil {
		t.Fatal(err)
	}
	if got := nextEv[TunnelRemoved](t, h); got.Name != "up" {
		t.Fatalf("TunnelRemoved %+v", got)
	}
	select {
	case got := <-c.unregCh:
		if got != id {
			t.Fatalf("unregistered %q, want %q", got, id)
		}
	case <-time.After(waitFor):
		t.Fatal("the server did not receive unregister")
	}
	if got := names(h.m.Snapshot()); len(got) != 0 {
		t.Fatalf("tunnel still in the set: %v", got)
	}

	// new streams for the removed tunnel are rejected without touching the local target
	st2 := c.openStream(t, "up")
	defer st2.Close()
	_ = st2.SetReadDeadline(time.Now().Add(waitFor))
	if data, _ := io.ReadAll(st2); len(data) != 0 {
		t.Fatalf("unexpected data on a stream of a removed tunnel: %q", data)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("local target saw %d connections, want 1", n)
	}

	// the old stream still works
	if _, err := io.WriteString(st1, "abc"); err != nil {
		t.Fatal(err)
	}
	_ = st1.Close()
	got, err := io.ReadAll(st1)
	if err != nil || string(got) != "ABC" {
		t.Fatalf("in-flight stream: %q, %v", got, err)
	}
}

func TestManagerRemoveWhileRegistrationInFlight(t *testing.T) {
	fs := newFakeServer(t)
	fs.regGate = make(chan struct{}, 8)
	h := startMgr(t, fs, nil, testTuning())
	nextEv[Connected](t, h)
	c := fs.conn(1)

	if _, err := h.m.Add(httpSpec("a", 8080)); err != nil {
		t.Fatal(err)
	}
	<-c.regCh // the register message reached the server, its reply is held back
	if err := h.m.Remove("a"); err != nil {
		t.Fatal(err)
	}
	fs.regGate <- struct{}{}
	select {
	case <-c.unregCh:
	case <-time.After(waitFor):
		t.Fatal("the registration that was answered after Remove was not unregistered")
	}
	if live := c.liveTunnels(); len(live) != 0 {
		t.Fatalf("server still has tunnels: %v", live)
	}
	noEv[TunnelReady](t, h, 100*time.Millisecond)
	if got := names(h.m.Snapshot()); len(got) != 0 {
		t.Fatalf("set %v", got)
	}
}

func TestManagerReplaceChangedWhileRegistrationInFlight(t *testing.T) {
	fs := newFakeServer(t)
	fs.regGate = make(chan struct{}, 8)
	h := startMgr(t, fs, nil, testTuning())
	nextEv[Connected](t, h)
	c := fs.conn(1)

	if _, err := h.m.Add(httpSpec("a", 8080)); err != nil {
		t.Fatal(err)
	}
	<-c.regCh
	added, removed, changed, err := h.m.Replace([]TunnelSpec{httpSpec("a", 8081)})
	if err != nil || len(added) != 0 || len(removed) != 0 || !slices.Equal(changed, []string{"a"}) {
		t.Fatalf("Replace: %v %v %v %v", added, removed, changed, err)
	}
	// the new registration must wait until the old one is answered and undone: the server (like the real one)
	// answers a second registration of a live name with name_taken
	select {
	case r := <-c.regCh:
		t.Fatalf("second registration sent while the first one is in flight: %+v", r)
	case <-time.After(150 * time.Millisecond):
	}
	fs.regGate <- struct{}{} // answer #1
	id1 := ""
	select {
	case id1 = <-c.unregCh:
	case <-time.After(waitFor):
		t.Fatal("no unregister for the replaced registration")
	}
	if r := <-c.regCh; r.Name != "a" {
		t.Fatalf("second registration %+v", r)
	}
	fs.regGate <- struct{}{} // answer #2
	ts := waitStatus(t, h.m, "a", StatusReady)
	if ts.Spec.LocalAddr != "127.0.0.1:8081" {
		t.Fatalf("ready tunnel has the old spec: %+v", ts)
	}
	regs := c.registrations()
	if len(regs) != 2 || id1 != "t1-1" || c.tunnelID("a") != "t1-2" {
		t.Fatalf("regs %+v, first id %q", regs, id1)
	}
	if live := c.liveTunnels(); !slices.Equal(live, []string{"a"}) {
		t.Fatalf("server tunnels %v", live)
	}
}

func TestManagerReplaceDiff(t *testing.T) {
	fs := newFakeServer(t)
	h := startMgr(t, fs, []TunnelSpec{
		httpSpec("a", 8080),
		tcpSpec("b", "127.0.0.1:5432"),
		tcpSpec("c", "127.0.0.1:22"),
	}, testTuning())
	for _, n := range []string{"a", "b", "c"} {
		waitStatus(t, h.m, n, StatusReady)
	}
	c := fs.conn(1)
	idA, idC := c.tunnelID("a"), c.tunnelID("c")

	added, removed, changed, err := h.m.Replace([]TunnelSpec{
		tcpSpec("d", "127.0.0.1:7000"),
		tcpSpec("c", "127.0.0.1:2222"), // changed
		tcpSpec("b", "127.0.0.1:5432"), // unchanged
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(added, []string{"d"}) || !slices.Equal(removed, []string{"a"}) || !slices.Equal(changed, []string{"c"}) {
		t.Fatalf("diff: added %v removed %v changed %v", added, removed, changed)
	}
	for _, n := range []string{"b", "c", "d"} {
		waitStatus(t, h.m, n, StatusReady)
	}
	eventually(t, "the server to see the final set", func() bool {
		return slices.Equal(c.liveTunnels(), []string{"b", "c", "d"})
	})

	var regNames []string
	for _, r := range c.registrations() {
		regNames = append(regNames, r.Name)
	}
	if want := []string{"a", "b", "c", "d", "c"}; !slices.Equal(regNames, want) {
		t.Fatalf("registrations %v, want %v (unchanged tunnel b must not be registered again)", regNames, want)
	}
	if ts, _ := tunnelOf(h.m, "c"); ts.Spec.LocalAddr != "127.0.0.1:2222" {
		t.Fatalf("changed tunnel keeps its old spec: %+v", ts)
	}
	unregs := c.unregistrations()
	slices.Sort(unregs)
	if want := []string{idA, idC}; !slices.Equal(unregs, want) {
		t.Fatalf("unregistered %v, want %v", unregs, want)
	}
	if n := fs.connCount(); n != 1 {
		t.Fatalf("Replace caused a reconnect (%d connections)", n)
	}
}

func TestManagerReplaceIsAtomicAndNormalizes(t *testing.T) {
	fs := newFakeServer(t)
	h := newMgr(t, fs, []TunnelSpec{httpSpec("a", 8080)}, testTuning())
	before := h.m.Snapshot()

	bad := [][]TunnelSpec{
		{httpSpec("x", 1), {Kind: "udp", LocalAddr: "127.0.0.1:1"}},
		{httpSpec("x", 1), httpSpec("x", 2)},
	}
	for i, specs := range bad {
		if _, _, _, err := h.m.Replace(specs); err == nil {
			t.Fatalf("case %d: expected an error", i)
		}
		if got := h.m.Snapshot(); !slices.Equal(names(got), names(before)) {
			t.Fatalf("case %d: a failed Replace changed the set: %v", i, names(got))
		}
	}

	// the default name is filled in before the diff: "http-8080" is the existing "a"? no, a different name
	added, removed, changed, err := h.m.Replace([]TunnelSpec{{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"}})
	if err != nil || !slices.Equal(added, []string{"http-8080"}) || !slices.Equal(removed, []string{"a"}) || len(changed) != 0 {
		t.Fatalf("Replace: %v %v %v %v", added, removed, changed, err)
	}
	// an empty set is valid and removes everything
	_, removed, _, err = h.m.Replace(nil)
	if err != nil || !slices.Equal(removed, []string{"http-8080"}) || len(h.m.Snapshot().Tunnels) != 0 {
		t.Fatalf("Replace(nil): %v %v", removed, err)
	}
}

func TestManagerSSHTunnel(t *testing.T) {
	fs := newFakeServer(t)
	spec := TunnelSpec{Kind: proto.KindSSH, LocalAddr: "127.0.0.1:22", Private: true}
	h := startMgr(t, fs, []TunnelSpec{spec}, testTuning())

	ready := nextEv[TunnelReady](t, h)
	if ready.Name != "ssh" || ready.SSHJump != "tun.test:2222" || ready.PublicURL != "" || !ready.Spec.Private {
		t.Fatalf("TunnelReady %+v", ready)
	}
	ts := waitStatus(t, h.m, "ssh", StatusReady)
	if ts.SSHJump != "tun.test:2222" {
		t.Errorf("state %+v", ts)
	}
	regs := fs.conn(1).registrations()
	if len(regs) != 1 || regs[0].Kind != proto.KindSSH || !regs[0].Private || regs[0].Name != "ssh" {
		t.Errorf("register messages %+v", regs)
	}
}

func TestManagerPrivateNotConfirmedIsAFailure(t *testing.T) {
	fs := newFakeServer(t)
	fs.ignorePrivate = true
	h := startMgr(t, fs, nil, testTuning())
	nextEv[Connected](t, h)
	if _, err := h.m.Add(TunnelSpec{Kind: proto.KindSSH, LocalAddr: "127.0.0.1:22", Private: true}); err != nil {
		t.Fatal(err)
	}

	closed := nextEv[TunnelClosed](t, h)
	if closed.Name != "ssh" || !strings.Contains(closed.Reason, "private") {
		t.Fatalf("TunnelClosed %+v", closed)
	}
	ts := waitStatus(t, h.m, "ssh", StatusFailed)
	if ts.Err == nil || ts.SSHJump != "" {
		t.Errorf("state %+v", ts)
	}
	select {
	case <-fs.conn(1).unregCh: // the tunnel the server did create is not left behind
	case <-time.After(waitFor):
		t.Fatal("the unconfirmed private tunnel was not unregistered")
	}
}

func TestManagerRefusedRegistrationIsFailedNotFatal(t *testing.T) {
	fs := newFakeServer(t)
	var refused atomic.Bool
	fs.regError = func(_ int, reg *proto.Register) *proto.Error {
		if reg.Name == "bad" && !refused.Swap(true) {
			return &proto.Error{Code: proto.CodeNameTaken, Message: "name is taken"}
		}
		return nil
	}
	h := startMgr(t, fs, []TunnelSpec{httpSpec("bad", 8080), httpSpec("good", 8081)}, testTuning())

	closed := nextEv[TunnelClosed](t, h)
	if closed.Name != "bad" || !strings.Contains(closed.Reason, "name_taken") {
		t.Fatalf("TunnelClosed %+v", closed)
	}
	waitStatus(t, h.m, "good", StatusReady)
	ts := waitStatus(t, h.m, "bad", StatusFailed)
	var perr *proto.Error
	if !errors.As(ts.Err, &perr) || perr.Code != proto.CodeNameTaken || ts.PublicURL != "" {
		t.Fatalf("failed tunnel state %+v", ts)
	}
	if !h.running() {
		t.Fatalf("Run ended: %v", h.err)
	}
	if st := h.m.Snapshot(); st.Conn != ConnConnected {
		t.Fatalf("state %+v", st)
	}
	noEv[Disconnected](t, h, 100*time.Millisecond)

	// a refusal of a tunnel added at run time behaves the same
	refused.Store(false)
	if _, err := h.m.Add(httpSpec("bad", 9000)); !errors.Is(err, ErrTunnelExists) {
		t.Fatalf("Add of a failed tunnel: %v", err)
	}
	if err := h.m.Remove("bad"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Add(httpSpec("bad", 9000)); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, h.m, "bad", StatusFailed)
	if !h.running() {
		t.Fatalf("Run ended: %v", h.err)
	}

	// Replace retries a failed tunnel whose spec did not change, and reports no difference
	added, removed, changed, err := h.m.Replace([]TunnelSpec{httpSpec("bad", 9000), httpSpec("good", 8081)})
	if err != nil || len(added)+len(removed)+len(changed) != 0 {
		t.Fatalf("Replace: %v %v %v %v", added, removed, changed, err)
	}
	waitStatus(t, h.m, "bad", StatusReady)
	if n := fs.connCount(); n != 1 {
		t.Fatalf("%d connections", n)
	}
}

func TestManagerFailedTunnelIsRetriedAfterReconnect(t *testing.T) {
	fs := newFakeServer(t)
	fs.regError = func(n int, reg *proto.Register) *proto.Error {
		if n == 1 && reg.Name == "bad" {
			return &proto.Error{Code: proto.CodeNameTaken, Message: "taken"}
		}
		return nil
	}
	h := startMgr(t, fs, []TunnelSpec{httpSpec("bad", 8080), httpSpec("good", 8081)}, testTuning())
	waitStatus(t, h.m, "bad", StatusFailed)
	waitStatus(t, h.m, "good", StatusReady)

	_ = fs.conn(1).sess.Close()
	nextEv[Disconnected](t, h)
	ts := waitStatus(t, h.m, "bad", StatusReady) // retried on the second session
	if ts.Err != nil {
		t.Fatalf("error not cleared: %+v", ts)
	}
	waitStatus(t, h.m, "good", StatusReady)
}

func TestManagerServerClosedTunnel(t *testing.T) {
	fs := newFakeServer(t)
	h := startMgr(t, fs, []TunnelSpec{httpSpec("web", 8080)}, testTuning())
	nextEv[TunnelReady](t, h)
	c := fs.conn(1)

	if err := c.send(&proto.TunnelClosed{TunnelID: c.tunnelID("web"), Reason: "quota"}); err != nil {
		t.Fatal(err)
	}
	if e := nextEv[TunnelClosed](t, h); e.Name != "web" || e.Reason != "quota" {
		t.Fatalf("TunnelClosed %+v", e)
	}
	ts, _ := tunnelOf(h.m, "web")
	if ts.Status != StatusFailed || ts.Err == nil || !strings.Contains(ts.Err.Error(), "quota") || ts.PublicURL != "" {
		t.Fatalf("tunnel state %+v", ts)
	}
	// unlike Run, a Manager keeps a session without tunnels
	noEv[Disconnected](t, h, 150*time.Millisecond)
	if fs.connCount() != 1 {
		t.Fatal("the session was re-established")
	}
	// ... and is not retried within the session, but after the next reconnect
	_ = c.sess.Close()
	nextEv[Disconnected](t, h)
	waitStatus(t, h.m, "web", StatusReady)
	if fs.connCount() != 2 {
		t.Fatalf("%d connections", fs.connCount())
	}
}

func TestManagerReconnectReRegistersCurrentSet(t *testing.T) {
	fs := newFakeServer(t)
	fs.handler = func(c *srvConn) {
		if c.n == 2 { // the server is "down" for a while: the client sits in backoff for >= 400 ms
			rejectHandler(&proto.Error{Code: proto.CodeInternal, RetryAfterMS: 400, Fatal: true})(c)
			return
		}
		fs.defaultHandler(c)
	}
	h := startMgr(t, fs, []TunnelSpec{httpSpec("keep", 8080), httpSpec("drop", 8081)}, testTuning())
	waitStatus(t, h.m, "keep", StatusReady)
	waitStatus(t, h.m, "drop", StatusReady)

	_ = fs.conn(1).sess.Close()
	nextEv[Disconnected](t, h) // session 1 lost
	d := nextEv[Disconnected](t, h)
	if d.RetryIn < 400*time.Millisecond {
		t.Fatalf("second Disconnected %+v", d)
	}
	st := h.m.Snapshot()
	if st.Conn != ConnBackoff || !st.RetryAt.After(time.Now()) || st.LastErr == nil {
		t.Fatalf("state in backoff: %+v", st)
	}
	for _, ts := range st.Tunnels {
		if ts.Status != StatusPending || ts.PublicURL != "" {
			t.Fatalf("tunnel not pending while disconnected: %+v", ts)
		}
	}

	// edit the set while the client is waiting
	if _, err := h.m.Add(httpSpec("late", 8082)); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Remove("drop"); err != nil {
		t.Fatal(err)
	}
	if a := nextEv[TunnelAdded](t, h); a.Spec.Name != "late" {
		t.Fatalf("%+v", a)
	}
	nextEv[TunnelRemoved](t, h)
	if st := h.m.Snapshot(); st.Conn != ConnBackoff {
		t.Fatalf("an edit during backoff must not end it: %+v", st)
	}

	waitStatus(t, h.m, "keep", StatusReady)
	waitStatus(t, h.m, "late", StatusReady)
	if fs.connCount() != 3 {
		t.Fatalf("%d connections", fs.connCount())
	}
	var got []string
	for _, r := range fs.conn(3).registrations() {
		got = append(got, r.Name)
	}
	if !slices.Equal(got, []string{"keep", "late"}) {
		t.Fatalf("third session registered %v", got)
	}
	if st := h.m.Snapshot(); st.Conn != ConnConnected || st.LastErr != nil || !st.RetryAt.IsZero() {
		t.Fatalf("state after reconnect: %+v", st)
	}
}

func TestManagerFatalErrorEndsRun(t *testing.T) {
	fs := newFakeServer(t)
	fs.handler = rejectHandler(&proto.Error{Code: proto.CodeUnauthorized, Message: "bad token", Fatal: true})
	h := startMgr(t, fs, []TunnelSpec{httpSpec("web", 8080)}, testTuning())

	err := h.result()
	var perr *proto.Error
	if !errors.As(err, &perr) || perr.Code != proto.CodeUnauthorized {
		t.Fatalf("Run returned %v", err)
	}
	st := h.m.Snapshot()
	if st.Conn != ConnStopped || !errors.Is(st.LastErr, err) || len(st.Tunnels) != 1 {
		t.Fatalf("state %+v", st)
	}
	if _, ok := <-h.events; ok {
		for range h.events { // drain: the channel must be closed once Run returned
		}
	}
	if _, err := h.m.Add(httpSpec("x", 1)); !errors.Is(err, ErrStopped) {
		t.Fatalf("Add after stop: %v", err)
	}
	if err := h.m.Remove("web"); !errors.Is(err, ErrStopped) {
		t.Fatalf("Remove after stop: %v", err)
	}
	if _, _, _, err := h.m.Replace(nil); !errors.Is(err, ErrStopped) {
		t.Fatalf("Replace after stop: %v", err)
	}
	if err := h.m.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Run: %v", err)
	}
	ch, cancel := h.m.Subscribe(1)
	defer cancel()
	if _, ok := <-ch; ok {
		t.Fatal("Subscribe after stop must return a closed channel")
	}
	if n := fs.connCount(); n != 1 {
		t.Fatalf("server saw %d connections", n)
	}
}

func TestManagerRunTwice(t *testing.T) {
	fs := newFakeServer(t)
	h := startMgr(t, fs, nil, testTuning())
	nextEv[Connected](t, h)
	if err := h.m.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Run: %v", err)
	}
}

func TestManagerCancelStops(t *testing.T) {
	fs := newFakeServer(t)
	h := startMgr(t, fs, []TunnelSpec{httpSpec("web", 8080)}, testTuning())
	nextEv[TunnelReady](t, h)
	h.cancel()
	if err := h.result(); err != nil {
		t.Fatalf("Run returned %v after cancel", err)
	}
	if st := h.m.Snapshot(); st.Conn != ConnStopped || st.LastErr != nil {
		t.Fatalf("state %+v", st)
	}
	select {
	case <-fs.conn(1).sess.Done():
	case <-time.After(waitFor):
		t.Fatal("server side session was not closed")
	}
}

func TestManagerInitialConnectError(t *testing.T) {
	opts := Options{
		ServerURL:          deadURL(t),
		Token:              newToken(t),
		Version:            "test",
		Logger:             slog.New(slog.DiscardHandler),
		MaxInitialAttempts: 2,
	}
	h := newMgrOpts(t, opts, testTuning()).start()
	err := h.result()
	var ice *InitialConnectError
	if !errors.As(err, &ice) || ice.Attempts != 2 {
		t.Fatalf("Run returned %v", err)
	}
	if st := h.m.Snapshot(); st.Conn != ConnStopped || st.LastErr == nil {
		t.Fatalf("state %+v", st)
	}
}

func TestManagerBackoffState(t *testing.T) {
	opts := Options{
		ServerURL: deadURL(t),
		Token:     newToken(t),
		Logger:    slog.New(slog.DiscardHandler),
	}
	tun := testTuning()
	tun.backoffBase, tun.backoffMax = 200*time.Millisecond, 200*time.Millisecond
	h := newMgrOpts(t, opts, tun).start()
	d := nextEv[Disconnected](t, h) // a failed attempt with no limit set: Run keeps going
	if d.Err == nil || d.Attempt != 1 || d.MaxAttempts != 0 {
		t.Fatalf("Disconnected %+v", d)
	}
	st := h.m.Snapshot()
	if st.Conn != ConnBackoff || st.LastErr == nil || st.RetryAt.IsZero() {
		t.Fatalf("state %+v", st)
	}
}

func TestManagerSubscribe(t *testing.T) {
	fs := newFakeServer(t)
	h := newMgr(t, fs, nil, testTuning())
	chA, cancelA := h.m.Subscribe(256)
	chB, cancelB := h.m.Subscribe(256)
	slow, cancelSlow := h.m.Subscribe(1) // never read: must not stall the session
	defer cancelSlow()
	h.start()

	const n = 20
	for i := range n {
		if _, err := h.m.Add(tcpSpec(fmt.Sprintf("t%02d", i), fmt.Sprintf("127.0.0.1:%d", 20000+i))); err != nil {
			t.Fatal(err)
		}
	}
	count := func(ch <-chan Event, want int) (ready int) {
		deadline := time.After(waitFor)
		for ready < want {
			select {
			case e, ok := <-ch:
				if !ok {
					t.Fatal("subscription closed")
				}
				if _, isReady := e.(TunnelReady); isReady {
					ready++
				}
			case <-deadline:
				t.Fatalf("got %d of %d TunnelReady events", ready, want)
			}
		}
		return ready
	}
	count(chA, n)
	if len(h.m.Snapshot().Tunnels) != n {
		t.Fatalf("snapshot has %d tunnels", len(h.m.Snapshot().Tunnels))
	}
	count(chB, n)

	// cancel closes the channel, is idempotent, and does not disturb the others
	cancelA()
	cancelA()
	if _, ok := <-chA; ok {
		for range chA { // events queued before the cancel may still be buffered
		}
	}
	if _, err := h.m.Add(tcpSpec("extra", "127.0.0.1:21000")); err != nil {
		t.Fatal(err)
	}
	count(chB, 1)
	select {
	case _, ok := <-slow:
		if !ok {
			t.Fatal("the slow subscription was closed")
		}
	default:
		t.Fatal("the slow subscriber received nothing at all")
	}
	cancelB()

	// stopping the Manager closes the remaining subscriptions after the last event
	h.cancel()
	_ = h.result()
	for range slow {
	}
}

func TestManagerSnapshotIsConsistentUnderChurn(t *testing.T) {
	fs := newFakeServer(t)
	h := startMgr(t, fs, nil, testTuning())
	nextEv[Connected](t, h)
	go func() { // keep the event channel drained
		for range h.events {
		}
	}()

	stop := make(chan struct{})
	var checker sync.WaitGroup
	checker.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			st := h.m.Snapshot()
			if !slices.IsSorted(names(st)) {
				t.Errorf("unsorted snapshot %v", names(st))
				return
			}
			for i, ts := range st.Tunnels {
				if i > 0 && st.Tunnels[i-1].Spec.Name == ts.Spec.Name {
					t.Errorf("duplicate tunnel in snapshot: %v", names(st))
					return
				}
				switch ts.Status {
				case StatusReady:
					if ts.PublicURL == "" || ts.Err != nil {
						t.Errorf("ready tunnel without URL or with an error: %+v", ts)
						return
					}
				case StatusFailed:
					if ts.Err == nil || ts.PublicURL != "" {
						t.Errorf("failed tunnel without an error: %+v", ts)
						return
					}
				case StatusPending:
					if ts.PublicURL != "" || ts.Err != nil {
						t.Errorf("pending tunnel with a URL or an error: %+v", ts)
						return
					}
				default:
					t.Errorf("unknown status %q", ts.Status)
					return
				}
			}
		}
	})

	var workers sync.WaitGroup
	for k := range 8 {
		workers.Go(func() {
			name := fmt.Sprintf("w%d", k)
			for i := range 40 {
				spec := httpSpec(name, 10000+i)
				if _, err := h.m.Add(spec); err != nil {
					t.Errorf("Add: %v", err)
					return
				}
				if i%2 == 0 { // some are removed right away, some after the registration may have been answered
					time.Sleep(time.Millisecond)
				}
				if err := h.m.Remove(name); err != nil {
					t.Errorf("Remove: %v", err)
					return
				}
			}
		})
	}
	workers.Wait()

	final := []TunnelSpec{httpSpec("f1", 1), tcpSpec("f2", "127.0.0.1:2"), httpSpec("f3", 3)}
	if _, _, _, err := h.m.Replace(final); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"f1", "f2", "f3"} {
		waitStatus(t, h.m, n, StatusReady)
	}
	c := fs.conn(1)
	eventually(t, "the server to hold exactly the final set", func() bool {
		return slices.Equal(c.liveTunnels(), []string{"f1", "f2", "f3"})
	})
	close(stop)
	checker.Wait()
	if n := fs.connCount(); n != 1 {
		t.Fatalf("churn caused a reconnect (%d connections)", n)
	}
	// the server never saw a name registered twice at the same time: that would have been answered with name_taken
	for _, ts := range h.m.Snapshot().Tunnels {
		if ts.Status != StatusReady {
			t.Fatalf("tunnel %+v", ts)
		}
	}
}

func TestManagerConcurrentAddRemove(t *testing.T) {
	fs := newFakeServer(t)
	h := startMgr(t, fs, nil, testTuning())
	nextEv[Connected](t, h)

	var wg sync.WaitGroup
	for k := range 16 {
		wg.Go(func() {
			name := fmt.Sprintf("c%d", k)
			for i := range 25 {
				if _, err := h.m.Add(httpSpec(name, 20000+i)); err != nil {
					t.Errorf("Add %s: %v", name, err)
					return
				}
				if err := h.m.Remove(name); err != nil {
					t.Errorf("Remove %s: %v", name, err)
					return
				}
			}
			if _, err := h.m.Add(httpSpec(name, 30000)); err != nil {
				t.Errorf("final Add %s: %v", name, err)
			}
			_ = h.m.Snapshot()
		})
	}
	wg.Wait()

	want := make([]string, 0, 16)
	for k := range 16 {
		want = append(want, fmt.Sprintf("c%d", k))
	}
	slices.Sort(want)
	for _, n := range want {
		waitStatus(t, h.m, n, StatusReady)
	}
	c := fs.conn(1)
	eventually(t, "the server to hold every tunnel", func() bool { return slices.Equal(c.liveTunnels(), want) })
}

// TestManagerEventsFromRunGoroutineOnly checks the documented guarantee for Options.OnEvent: events caused by
// calls from many goroutines are still delivered one at a time (a data race here is reported by -race).
func TestManagerEventsFromRunGoroutineOnly(t *testing.T) {
	fs := newFakeServer(t)
	var events []Event // deliberately unsynchronised
	h := startMgr(t, fs, nil, testTuning(), func(o *Options) { o.OnEvent = func(e Event) { events = append(events, e) } })
	nextEv[Connected](t, h)

	var wg sync.WaitGroup
	for k := range 8 {
		wg.Go(func() {
			if _, err := h.m.Add(httpSpec(fmt.Sprintf("n%d", k), 8000+k)); err != nil {
				t.Errorf("Add: %v", err)
			}
		})
	}
	wg.Wait()
	for k := range 8 {
		waitStatus(t, h.m, fmt.Sprintf("n%d", k), StatusReady)
	}
	h.cancel()
	_ = h.result() // the happens-before edge that makes reading events safe

	added := map[string]int{}
	var ready int
	for i, e := range events {
		switch e := e.(type) {
		case TunnelAdded:
			added[e.Spec.Name] = i
		case TunnelReady:
			ready++
			if at, ok := added[e.Name]; !ok || at > i {
				t.Fatalf("TunnelReady for %q before its TunnelAdded", e.Name)
			}
		}
	}
	if len(added) != 8 || ready != 8 {
		t.Fatalf("got %d TunnelAdded and %d TunnelReady events", len(added), ready)
	}
	if _, ok := events[0].(Connected); !ok {
		t.Fatalf("first event %T", events[0])
	}
}
