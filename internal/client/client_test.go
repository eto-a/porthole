// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/eto-a/porthole/internal/proto"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

const waitFor = 5 * time.Second

func testTuning() tuning {
	t := defaultTuning()
	t.backoffBase = 5 * time.Millisecond
	t.backoffMax = 20 * time.Millisecond
	t.stableAfter = time.Hour
	t.dialTimeout = 3 * time.Second
	t.handshakeTimeout = 3 * time.Second
	t.registerTimeout = 3 * time.Second
	return t
}

// harness runs Run against a fake server and exposes its events.
type harness struct {
	t      *testing.T
	events chan Event
	done   chan error
	cancel context.CancelFunc
}

func startClient(t *testing.T, fs *fakeServer, specs []TunnelSpec, tun tuning) *harness {
	t.Helper()
	h := &harness{t: t, events: make(chan Event, 256), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	opts := Options{
		ServerURL: fs.url(),
		Token:     newToken(t),
		Tunnels:   specs,
		Version:   "test",
		Logger:    slog.New(slog.DiscardHandler),
		OnEvent:   func(e Event) { h.events <- e },
	}
	go func() { h.done <- run(ctx, opts, tun) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(waitFor):
			t.Error("Run did not return after cancel")
		}
	})
	return h
}

// next returns the next event of the wanted type, failing on timeout; events of other types are skipped.
func next[T Event](t *testing.T, h *harness) T {
	t.Helper()
	deadline := time.After(waitFor)
	for {
		select {
		case e := <-h.events:
			if v, ok := e.(T); ok {
				return v
			}
		case err := <-h.done:
			var zero T
			t.Fatalf("Run returned (%v) while waiting for %T", err, zero)
		case <-deadline:
			var zero T
			t.Fatalf("timed out waiting for %T", zero)
		}
	}
}

func waitConn(t *testing.T, ch <-chan *srvConn) *srvConn {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(waitFor):
		t.Fatal("timed out waiting for a connection")
		return nil
	}
}

// upperServer listens on a local port, reads each connection until EOF, replies with the upper-cased data and
// closes. It therefore only answers once the client propagated the half-close.
func upperServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
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
	return ln.Addr().String()
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestRegistrationAndEvents(t *testing.T) {
	fs := newFakeServer(t)
	fs.expectRegs = 2
	h := startClient(t, fs, []TunnelSpec{
		{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"},
		{Kind: proto.KindTCP, Name: "ssh", LocalAddr: "127.0.0.1:22", RemotePort: 20017},
	}, testTuning())

	if c := next[Connected](t, h); c.ClientName != "home" {
		t.Fatalf("client name %q", c.ClientName)
	}
	r1 := next[TunnelReady](t, h)
	if r1.Name != "http-8080" || r1.Spec.Name != "http-8080" || r1.PublicURL != "https://http-8080-home.tun.test" {
		t.Fatalf("first tunnel: %+v", r1)
	}
	r2 := next[TunnelReady](t, h)
	if r2.Name != "ssh" || r2.PublicURL != "tcp://tun.test:20017" || r2.Spec.RemotePort != 20017 {
		t.Fatalf("second tunnel: %+v", r2)
	}

	c := waitConn(t, fs.ready)
	if c.hello.ProtocolVersion != proto.Version || c.hello.ClientVersion != "test" ||
		c.hello.OS != runtime.GOOS+"/"+runtime.GOARCH || !strings.HasPrefix(c.hello.Token, "ph_") {
		t.Fatalf("unexpected hello: %+v", c.hello)
	}
	regs := c.registrations()
	if len(regs) != 2 || regs[0].Kind != proto.KindHTTP || regs[0].Name != "http-8080" ||
		regs[1].Kind != proto.KindTCP || regs[1].Name != "ssh" || regs[1].RemotePort != 20017 {
		t.Fatalf("unexpected registrations: %+v", regs)
	}
	if regs[0].ReqID == regs[1].ReqID || regs[0].ReqID <= 0 {
		t.Fatalf("req ids must be distinct and positive: %d %d", regs[0].ReqID, regs[1].ReqID)
	}
}

func TestStreamForwarding(t *testing.T) {
	local := upperServer(t)
	fs := newFakeServer(t)
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindTCP, Name: "up", LocalAddr: local}}, testTuning())
	next[TunnelReady](t, h)
	c := waitConn(t, fs.ready)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			st := c.openStream(t, "up")
			defer st.Close()
			_ = st.SetDeadline(time.Now().Add(waitFor))
			msg := strings.Repeat("hello-", 1+i*5000) // up to ~200 KiB: more than one yamux window
			go func() {
				_, _ = io.WriteString(st, msg)
				_ = st.Close() // half-close: the local server only answers after EOF
			}()
			got, err := io.ReadAll(st)
			if err != nil {
				t.Errorf("stream %d read: %v", i, err)
				return
			}
			if want := strings.ToUpper(msg); string(got) != want {
				t.Errorf("stream %d: got %d bytes, want %d", i, len(got), len(want))
			}
		})
	}
	wg.Wait()
}

func TestLocalDialFailureClosesStream(t *testing.T) {
	fs := newFakeServer(t)
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindTCP, Name: "dead", LocalAddr: freeAddr(t)}}, testTuning())
	next[TunnelReady](t, h)
	c := waitConn(t, fs.ready)

	st := c.openStream(t, "dead")
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(waitFor))
	got, err := io.ReadAll(st)
	if len(got) != 0 {
		t.Fatalf("unexpected data %q (err %v)", got, err)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("read ended with %v", err) // a reset is acceptable, a timeout is not
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
			t.Fatalf("stream was not closed: %v", err)
		}
	}
}

func TestUnauthorizedIsFatal(t *testing.T) {
	fs := newFakeServer(t)
	fs.handler = rejectHandler(&proto.Error{Code: proto.CodeUnauthorized, Message: "bad token", Fatal: true})
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"}}, testTuning())

	select {
	case err := <-h.done:
		var perr *proto.Error
		if !errors.As(err, &perr) || perr.Code != proto.CodeUnauthorized {
			t.Fatalf("Run returned %v, want unauthorized *proto.Error", err)
		}
		h.done <- err // let the cleanup see a finished Run
	case <-time.After(waitFor):
		t.Fatal("Run did not return")
	}
	time.Sleep(150 * time.Millisecond) // a retrying client would have reconnected by now
	if n := fs.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1", n)
	}
	for len(h.events) > 0 {
		if e := <-h.events; isDisconnected(e) {
			t.Fatalf("unexpected event %+v", e)
		}
	}
}

func isDisconnected(e Event) bool { _, ok := e.(Disconnected); return ok }

func TestRegistrationRefusedOnFirstConnectionIsFatal(t *testing.T) {
	fs := newFakeServer(t)
	fs.regError = func(_ int, reg *proto.Register) *proto.Error {
		return &proto.Error{Code: proto.CodeNameTaken, Message: "name " + reg.Name + " is taken"}
	}
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindHTTP, Name: "blog", LocalAddr: "127.0.0.1:8080"}}, testTuning())

	select {
	case err := <-h.done:
		var perr *proto.Error
		if !errors.As(err, &perr) || perr.Code != proto.CodeNameTaken {
			t.Fatalf("Run returned %v, want name_taken", err)
		}
		h.done <- err
	case <-time.After(waitFor):
		t.Fatal("Run did not return")
	}
	if n := fs.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1", n)
	}
}

func TestReconnectReRegisters(t *testing.T) {
	fs := newFakeServer(t)
	fs.expectRegs = 2
	tun := testTuning()
	h := startClient(t, fs, []TunnelSpec{
		{Kind: proto.KindHTTP, Name: "web", LocalAddr: "127.0.0.1:8080"},
		{Kind: proto.KindTCP, Name: "db", LocalAddr: "127.0.0.1:5432"},
	}, tun)
	next[TunnelReady](t, h)
	next[TunnelReady](t, h)
	first := waitConn(t, fs.ready)

	_ = first.sess.Close() // the server drops the connection

	d := next[Disconnected](t, h)
	if d.Err == nil || d.RetryIn < 0 || d.RetryIn > tun.backoffMax {
		t.Fatalf("unexpected Disconnected: %+v", d)
	}
	next[Connected](t, h)
	if r := next[TunnelReady](t, h); r.Name != "web" {
		t.Fatalf("after reconnect: %+v", r)
	}
	if r := next[TunnelReady](t, h); r.Name != "db" {
		t.Fatalf("after reconnect: %+v", r)
	}
	second := waitConn(t, fs.ready)
	if second == first || len(second.registrations()) != 2 {
		t.Fatalf("second connection did not re-register: %+v", second.registrations())
	}
}

func TestReconnectRegistrationFailureIsEvent(t *testing.T) {
	fs := newFakeServer(t)
	fs.expectRegs = 2
	fs.regError = func(n int, reg *proto.Register) *proto.Error {
		if n == 2 && reg.Name == "web" {
			return &proto.Error{Code: proto.CodeNameTaken, Message: "taken"}
		}
		return nil
	}
	h := startClient(t, fs, []TunnelSpec{
		{Kind: proto.KindHTTP, Name: "web", LocalAddr: "127.0.0.1:8080"},
		{Kind: proto.KindTCP, Name: "db", LocalAddr: "127.0.0.1:5432"},
	}, testTuning())
	next[TunnelReady](t, h)
	next[TunnelReady](t, h)
	first := waitConn(t, fs.ready)
	_ = first.sess.Close()

	next[Disconnected](t, h)
	next[Connected](t, h)
	closed := next[TunnelClosed](t, h)
	if closed.Name != "web" || !strings.Contains(closed.Reason, "name_taken") {
		t.Fatalf("unexpected TunnelClosed: %+v", closed)
	}
	if r := next[TunnelReady](t, h); r.Name != "db" {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	fs := newFakeServer(t)
	fs.handler = func(c *srvConn) {
		if c.n == 1 {
			rejectHandler(&proto.Error{Code: proto.CodeInternal, RetryAfterMS: 250, Fatal: true})(c)
			return
		}
		fs.defaultHandler(c)
	}
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"}}, testTuning())

	d := next[Disconnected](t, h)
	if d.RetryIn < 250*time.Millisecond {
		t.Fatalf("RetryIn %v ignores retry_after_ms", d.RetryIn)
	}
	next[TunnelReady](t, h)
	if gap := fs.conn(2).at.Sub(fs.conn(1).at); gap < 250*time.Millisecond {
		t.Fatalf("reconnected after %v, want >= 250ms", gap)
	}
}

func TestCancelShutsDownCleanly(t *testing.T) {
	local := upperServer(t)
	fs := newFakeServer(t)
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindTCP, Name: "up", LocalAddr: local}}, testTuning())
	next[TunnelReady](t, h)
	c := waitConn(t, fs.ready)

	// leave a stream open and idle so that there is a forwarding goroutine to stop
	st := c.openStream(t, "up")
	defer st.Close()
	time.Sleep(50 * time.Millisecond)

	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel, want nil", err)
		}
		h.done <- nil
	case <-time.After(waitFor):
		t.Fatal("Run did not return after cancel")
	}
	select {
	case <-c.sess.Done():
	case <-time.After(waitFor):
		t.Fatal("server side session was not closed")
	}
	// goleak (TestMain) verifies that nothing is left running
}

func TestPingPong(t *testing.T) {
	fs := newFakeServer(t)
	fs.hbMS = 50
	fs.pingIn = 20 * time.Millisecond
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"}}, testTuning())
	next[TunnelReady](t, h)
	c := waitConn(t, fs.ready)

	// pings keep coming, so the session must outlive several heartbeat timeouts (3 x 50 ms)
	deadline := time.After(waitFor)
	var seqs []uint64
	for len(seqs) < 20 {
		select {
		case s := <-c.pongs:
			seqs = append(seqs, s)
		case <-deadline:
			t.Fatalf("got only %d pongs", len(seqs))
		}
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("pong sequence %v is not 1..n", seqs)
		}
	}
	if n := fs.connCount(); n != 1 {
		t.Fatalf("client reconnected %d times while pings were flowing", n-1)
	}
}

func TestMissingPingTriggersReconnect(t *testing.T) {
	fs := newFakeServer(t)
	fs.hbMS = 30 // timeout 90 ms; the fake server never pings
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"}}, testTuning())
	next[TunnelReady](t, h)

	d := next[Disconnected](t, h)
	if d.Err == nil || !strings.Contains(d.Err.Error(), "no ping") {
		t.Fatalf("unexpected Disconnected: %+v", d)
	}
	next[Connected](t, h)
	if fs.connCount() < 2 {
		t.Fatal("client did not reconnect")
	}
}

func TestUnknownControlMessageIsIgnored(t *testing.T) {
	fs := newFakeServer(t)
	h := startClient(t, fs, []TunnelSpec{{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"}}, testTuning())
	next[TunnelReady](t, h)
	c := waitConn(t, fs.ready)

	if err := c.rawFrame(`{"type":"from_the_future","x":1}`); err != nil {
		t.Fatal(err)
	}
	if err := c.send(&proto.Ping{Seq: 77}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-c.pongs:
		if s != 77 {
			t.Fatalf("pong seq %d", s)
		}
	case <-time.After(waitFor):
		t.Fatal("no pong after an unknown message")
	}
}

func TestTunnelClosedByServer(t *testing.T) {
	fs := newFakeServer(t)
	fs.expectRegs = 2
	h := startClient(t, fs, []TunnelSpec{
		{Kind: proto.KindHTTP, Name: "web", LocalAddr: "127.0.0.1:8080"},
		{Kind: proto.KindTCP, Name: "db", LocalAddr: "127.0.0.1:5432"},
	}, testTuning())
	next[TunnelReady](t, h)
	next[TunnelReady](t, h)
	c := waitConn(t, fs.ready)

	if err := c.send(&proto.TunnelClosed{TunnelID: c.tunnelID("web"), Reason: "quota"}); err != nil {
		t.Fatal(err)
	}
	if e := next[TunnelClosed](t, h); e.Name != "web" || e.Reason != "quota" {
		t.Fatalf("unexpected: %+v", e)
	}
	if fs.connCount() != 1 {
		t.Fatal("one remaining tunnel must keep the session")
	}

	// when the last tunnel goes the session is re-established so that tunnels come back
	if err := c.send(&proto.TunnelClosed{TunnelID: c.tunnelID("db"), Reason: "quota"}); err != nil {
		t.Fatal(err)
	}
	next[TunnelClosed](t, h)
	if d := next[Disconnected](t, h); !errors.Is(d.Err, errAllTunnelsClosed) {
		t.Fatalf("unexpected: %+v", d)
	}
}

func TestInvalidOptions(t *testing.T) {
	good := Options{
		ServerURL: "http://127.0.0.1:1",
		Token:     newToken(t),
		Tunnels:   []TunnelSpec{{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"}},
	}
	cases := map[string]func(*Options){
		"bad url":   func(o *Options) { o.ServerURL = "ftp://x" },
		"bad token": func(o *Options) { o.Token = "nope" },
		"no tunnel": func(o *Options) { o.Tunnels = nil },
		"bad kind":  func(o *Options) { o.Tunnels[0].Kind = "udp" },
	}
	for name, mut := range cases {
		o := good
		o.Tunnels = append([]TunnelSpec(nil), good.Tunnels...)
		mut(&o)
		if err := Run(context.Background(), o); err == nil {
			t.Errorf("%s: Run returned nil", name)
		}
	}
}

func TestCheck(t *testing.T) {
	fs := newFakeServer(t)
	reject := rejectHandler(&proto.Error{Code: proto.CodeUnauthorized, Fatal: true})
	fs.handler = func(c *srvConn) {
		if c.n > 1 {
			reject(c)
			return
		}
		if c.handshake() {
			_ = c.replyOK()
		}
	}
	res, err := Check(context.Background(), Options{ServerURL: fs.url(), Token: newToken(t)})
	if err != nil {
		t.Fatal(err)
	}
	if res.ClientName != "home" || res.ServerVersion != "fake" {
		t.Fatalf("unexpected result %+v", res)
	}

	_, err = Check(context.Background(), Options{ServerURL: fs.url(), Token: newToken(t)})
	var perr *proto.Error
	if !errors.As(err, &perr) || perr.Code != proto.CodeUnauthorized {
		t.Fatalf("Check error = %v, want unauthorized", err)
	}
}

func TestBackoffDelay(t *testing.T) {
	base, maxD := time.Second, 60*time.Second
	for attempt := range 80 {
		limit := min(base<<min(attempt, 6), maxD)
		for range 50 {
			d := backoffDelay(attempt, base, maxD)
			if d < 0 || d >= limit {
				t.Fatalf("attempt %d: delay %v outside [0,%v)", attempt, d, limit)
			}
		}
	}
	var biggest time.Duration
	for range 2000 {
		biggest = max(biggest, backoffDelay(20, base, maxD))
	}
	if biggest < 30*time.Second {
		t.Fatalf("jitter does not use the whole range: max %v", biggest)
	}
}

func TestConnectURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://tun.example.com", "wss://tun.example.com/_porthole/v1/connect"},
		{"https://tun.example.com/", "wss://tun.example.com/_porthole/v1/connect"},
		{"http://127.0.0.1:8080", "ws://127.0.0.1:8080/_porthole/v1/connect"},
		{"https://example.com/porthole/", "wss://example.com/porthole/_porthole/v1/connect"},
	}
	for _, c := range cases {
		got, err := ConnectURL(c.in)
		if err != nil || got != c.want {
			t.Errorf("ConnectURL(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "tun.example.com", "ftp://x", "https://", "wss://x", "https://u:p@x"} {
		if got, err := ConnectURL(bad); err == nil {
			t.Errorf("ConnectURL(%q) = %q, want error", bad, got)
		}
	}
}

func TestNormalizeSpecs(t *testing.T) {
	got, err := normalizeSpecs([]TunnelSpec{
		{Kind: "tcp", LocalAddr: "10.0.0.5:7575"},
		{Kind: "http", LocalAddr: "[::1]:3000"},
	})
	if err != nil || got[0].Name != "tcp-7575" || got[1].Name != "http-3000" {
		t.Fatalf("got %+v, %v", got, err)
	}
	bad := [][]TunnelSpec{
		{{Kind: "http", LocalAddr: "8080"}},
		{{Kind: "http", LocalAddr: "h:0"}},
		{{Kind: "http", LocalAddr: "h:80", Name: "Bad_Name"}},
		{{Kind: "http", LocalAddr: "h:80", RemotePort: 1000}},
		{{Kind: "tcp", LocalAddr: "h:80", RemotePort: 70000}},
		{{Kind: "tcp", LocalAddr: "h:80"}, {Kind: "tcp", LocalAddr: "h:80"}},
	}
	for i, b := range bad {
		if _, err := normalizeSpecs(b); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
