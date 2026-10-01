// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

// seenRequest is what a backend observed.
type seenRequest struct {
	host   string
	path   string
	header http.Header
}

// recordingBackend answers "hello <path>" and reports every request it sees.
func recordingBackend(t *testing.T) (*httptest.Server, <-chan seenRequest) {
	t.Helper()
	seen := make(chan seenRequest, 16)
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- seenRequest{host: r.Host, path: r.URL.RequestURI(), header: r.Header.Clone()}
		w.Header().Set("X-Backend", "yes")
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	t.Cleanup(b.Close)
	return b, seen
}

// startEcho runs a TCP echo server that, like many real servers, answers until the peer half-closes.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return ln.Addr().String()
}

func TestHTTPTunnelEndToEnd(t *testing.T) {
	h := newHarness(t)
	backend, seen := recordingBackend(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "web", 0)
	if reg.PublicURL != "https://web-home.example.test" || reg.Name != "web" || reg.Kind != proto.KindHTTP || reg.TunnelID == "" {
		t.Fatalf("unexpected registered: %+v", reg)
	}
	c.serve(forward(backend.Listener.Addr().String()))

	resp, body := h.get("web-home.example.test", "/foo?x=1", http.Header{
		"X-Forwarded-For":   {"6.6.6.6"},
		"X-Forwarded-Host":  {"evil.example"},
		"X-Forwarded-Proto": {"gopher"},
		"Forwarded":         {"for=6.6.6.6"},
	})
	if resp.StatusCode != http.StatusOK || body != "hello /foo" || resp.Header.Get("X-Backend") != "yes" {
		t.Fatalf("status %d body %q headers %v", resp.StatusCode, body, resp.Header)
	}
	got := <-seen
	if got.host != "web-home.example.test" {
		t.Errorf("backend Host = %q, want the visitor's host", got.host)
	}
	if got.path != "/foo?x=1" {
		t.Errorf("backend path = %q", got.path)
	}
	if v := got.header.Get("X-Forwarded-For"); v != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want 127.0.0.1 (visitor-supplied value must be dropped)", v)
	}
	if v := got.header.Get("X-Forwarded-Host"); v != "web-home.example.test" {
		t.Errorf("X-Forwarded-Host = %q", v)
	}
	if v := got.header.Get("X-Forwarded-Proto"); v != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", v)
	}
	if v := got.header.Get("Forwarded"); v != "" {
		t.Errorf("Forwarded = %q, want it stripped", v)
	}

	hdr := <-c.headers
	if hdr.TunnelID != reg.TunnelID {
		t.Errorf("stream tunnel_id = %q, want %q", hdr.TunnelID, reg.TunnelID)
	}
	if host, _, err := net.SplitHostPort(hdr.RemoteAddr); err != nil || host != "127.0.0.1" {
		t.Errorf("stream remote_addr = %q", hdr.RemoteAddr)
	}
}

func TestHTTPHostRouting(t *testing.T) {
	h := newHarness(t)
	backend, _ := recordingBackend(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(forward(backend.Listener.Addr().String()))

	// Case and port do not matter.
	if resp, body := h.get("WEB-Home.Example.TEST:8443", "/x", nil); resp.StatusCode != http.StatusOK || body != "hello /x" {
		t.Errorf("mixed-case host with port: %d %q", resp.StatusCode, body)
	}

	notFound := []string{
		"nope-home.example.test",       // unknown label
		"a.web-home.example.test",      // two labels
		"web-home.other.test",          // foreign domain
		"example.test.evil.test",       // domain as a prefix only
		"web-home.example.test.evil.x", // ditto
		"127.0.0.1",
		"",
	}
	for _, host := range notFound {
		if resp, _ := h.get(host, "/", nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("Host %q: status %d, want 404", host, resp.StatusCode)
		}
	}

	// The bare domain: only /healthz and the connect path exist.
	resp, body := h.get("example.test", "/healthz", nil)
	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Errorf("/healthz: %d %q", resp.StatusCode, body)
	}
	if resp, _ := h.get("EXAMPLE.test:443", "/healthz", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz with mixed-case host: %d", resp.StatusCode)
	}
	if resp, _ := h.get("example.test", "/", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("/: %d, want 404", resp.StatusCode)
	}
	// /healthz on a tunnel host is the tunnel's business, not ours.
	if _, body := h.get("web-home.example.test", "/healthz", nil); body != "hello /healthz" {
		t.Errorf("tunnel /healthz body %q", body)
	}
	// A plain GET on the connect path is not a WebSocket upgrade.
	if resp, _ := h.get("example.test", proto.ConnectPath, nil); resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("connect path without upgrade: %d, want 4xx", resp.StatusCode)
	}
}

func TestHTTPTunnelPublicURLWithPort(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) {
		cfg.PublicScheme = "http"
		cfg.PublicPort = 8080
	})
	c := h.login(h.st.newToken(t, "home"))
	if got := c.mustRegister(proto.KindHTTP, "blog", 0).PublicURL; got != "http://blog-home.example.test:8080" {
		t.Errorf("public_url = %q", got)
	}
}

func TestWebSocketThroughHTTPTunnel(t *testing.T) {
	h := newHarness(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			typ, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if err := conn.Write(r.Context(), typ, append([]byte("echo:"), data...)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(backend.Close)

	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "ws", 0)
	c.serve(forward(backend.Listener.Addr().String()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, h.web.URL, &websocket.DialOptions{Host: "ws-home.example.test"})
	if err != nil {
		t.Fatalf("websocket dial through the tunnel: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	defer conn.CloseNow()
	for _, msg := range []string{"one", "two"} {
		if err := conn.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		typ, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if typ != websocket.MessageText || string(data) != "echo:"+msg {
			t.Fatalf("got %v %q", typ, data)
		}
	}
	if err := conn.Close(websocket.StatusNormalClosure, "bye"); err != nil {
		t.Logf("close: %v", err)
	}
}

func TestTCPTunnelEcho(t *testing.T) {
	h := newHarness(t)
	echo := startEcho(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindTCP, "echo", 0)
	c.serve(forward(echo))

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(reg.PublicURL, "tcp://"))
	if err != nil || host != testDomain {
		t.Fatalf("public_url = %q", reg.PublicURL)
	}
	var port int
	if _, err := fmt.Sscan(portStr, &port); err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	if port < h.lo || port > h.hi {
		t.Fatalf("port %d outside [%d,%d]", port, h.lo, h.hi)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	payload := bytes.Repeat([]byte("0123456789abcdef"), 16<<10) // 256 KiB
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite() // half-close: the echo must still come back
		}
		errc <- err
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-errc; werr != nil {
		t.Fatal(werr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, want %d identical bytes", len(got), len(payload))
	}
	hdr := <-c.headers
	if hdr.TunnelID != reg.TunnelID || !strings.HasPrefix(hdr.RemoteAddr, "127.0.0.1:") {
		t.Errorf("stream header %+v", hdr)
	}
}

func TestTCPPortAllocation(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))

	first := c.mustRegister(proto.KindTCP, "ssh", 0)
	port := publicPort(t, first.PublicURL)

	// Outside the range, or already taken: port_unavailable.
	for _, p := range []int{h.lo - 1, h.hi + 1, 22, port} {
		if e := c.registerErr(proto.KindTCP, fmt.Sprintf("p%d", p), p); e.Code != proto.CodePortUnavailable {
			t.Errorf("port %d: got %+v, want port_unavailable", p, e)
		}
	}
	// A specific free port inside the range works.
	want := 0
	for p := h.lo; p <= h.hi && want == 0; p++ {
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil && p != port {
			_ = ln.Close()
			want = p
		} else if err == nil {
			_ = ln.Close()
		}
	}
	if want == 0 {
		t.Skip("no second free port in the range")
	}
	if got := publicPort(t, c.mustRegister(proto.KindTCP, "pinned", want).PublicURL); got != want {
		t.Errorf("requested %d, got %d", want, got)
	}

	// After unregister the same name gets the same port back, even if another port is just as free.
	if err := c.write(&proto.Unregister{TunnelID: first.TunnelID}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unregister", func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return false
		}
		return true
	})
	if got := publicPort(t, c.mustRegister(proto.KindTCP, "ssh", 0).PublicURL); got != port {
		t.Errorf("re-registered ssh got port %d, want the reserved %d", got, port)
	}
}

func publicPort(t *testing.T, publicURL string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(strings.TrimPrefix(publicURL, "tcp://"))
	if err != nil {
		t.Fatalf("bad public_url %q", publicURL)
	}
	var port int
	if _, err := fmt.Sscan(p, &port); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestTCPPortExhaustion(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) {
		cfg.MaxTunnelsPerClient = 100
	})
	c := h.login(h.st.newToken(t, "home"))
	used := map[int]bool{}
	for i := range h.hi - h.lo + 1 {
		reg := c.register(proto.KindTCP, fmt.Sprintf("t%d", i), 0)
		r, ok := reg.(*proto.Registered)
		if !ok {
			// A port of the range may be held by an unrelated local process; stop at the first refusal.
			t.Logf("tunnel %d refused: %+v", i, reg)
			break
		}
		p := publicPort(t, r.PublicURL)
		if used[p] {
			t.Fatalf("port %d handed out twice", p)
		}
		used[p] = true
	}
	if len(used) == 0 {
		t.Fatal("no port could be allocated")
	}
	if len(used) == h.hi-h.lo+1 {
		if e := c.registerErr(proto.KindTCP, "one-too-many", 0); e.Code != proto.CodePortUnavailable {
			t.Errorf("exhausted range: got %+v, want port_unavailable", e)
		}
	}
}

func TestNameTaken(t *testing.T) {
	h := newHarness(t)
	// Label = <name>-<client>: client "c-a" with name "b" and client "a" with name "b-c" both want "b-c-a".
	ca := h.login(h.st.newToken(t, "c-a"))
	a := h.login(h.st.newToken(t, "a"))
	first := ca.mustRegister(proto.KindHTTP, "b", 0)
	if e := a.registerErr(proto.KindHTTP, "b-c", 0); e.Code != proto.CodeNameTaken {
		t.Errorf("other client: got %+v, want name_taken", e)
	}
	// The same client registering the same name twice.
	if e := ca.registerErr(proto.KindHTTP, "b", 0); e.Code != proto.CodeNameTaken {
		t.Errorf("same session: got %+v, want name_taken", e)
	}
	// A different name is fine, and once the owner lets go the label is free for others.
	a.mustRegister(proto.KindHTTP, "other", 0)
	if err := ca.write(&proto.Unregister{TunnelID: first.TunnelID}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unregister", func() bool { return h.srv.tunnelCount() == 1 })
	a.mustRegister(proto.KindHTTP, "b-c", 0)
}

func TestRegisterValidation(t *testing.T) {
	h := newHarness(t)
	long := strings.Repeat("a", 32)
	c := h.login(h.st.newToken(t, long))

	for _, bad := range []string{"Bad_Name", "-lead", "trail-", "with.dot", strings.Repeat("x", 33), "ünï"} {
		if e := c.registerErr(proto.KindHTTP, bad, 0); e.Code != proto.CodeInvalidRequest {
			t.Errorf("name %q: got %+v, want invalid_request", bad, e)
		}
	}
	// 32 + 1 + 32 = 65 characters: not a DNS label.
	if e := c.registerErr(proto.KindHTTP, strings.Repeat("b", 32), 0); e.Code != proto.CodeInvalidRequest {
		t.Errorf("65-char label: got %+v, want invalid_request", e)
	}
	if e := c.registerErr(proto.KindUDP, "dns", 0); e.Code != proto.CodeInvalidRequest || !strings.Contains(e.Message, "v0.2") {
		t.Errorf("udp: got %+v", e)
	}
	if e := c.registerErr("carrier-pigeon", "x", 0); e.Code != proto.CodeInvalidRequest {
		t.Errorf("unknown kind: got %+v", e)
	}
	if e := c.registerErr(proto.KindHTTP, "web", 20000); e.Code != proto.CodeInvalidRequest {
		t.Errorf("remote_port on http: got %+v", e)
	}
	// An omitted name gets a server-chosen default.
	if reg := c.mustRegister(proto.KindTCP, "", 0); !strings.HasPrefix(reg.Name, "tcp-") || !auth.ValidName(reg.Name) {
		t.Errorf("default name %q", reg.Name)
	}
}

func TestScopes(t *testing.T) {
	h := newHarness(t)
	httpOnly := h.login(h.st.newToken(t, "web", func(tk *store.Token) { tk.Scopes = []string{auth.ScopeTunnelHTTP} }))
	if e := httpOnly.registerErr(proto.KindTCP, "x", 0); e.Code != proto.CodeForbidden {
		t.Errorf("tcp without scope: %+v", e)
	}
	httpOnly.mustRegister(proto.KindHTTP, "x", 0)

	tcpOnly := h.login(h.st.newToken(t, "raw", func(tk *store.Token) { tk.Scopes = []string{auth.ScopeTunnelTCP} }))
	if e := tcpOnly.registerErr(proto.KindHTTP, "x", 0); e.Code != proto.CodeForbidden {
		t.Errorf("http without scope: %+v", e)
	}
	tcpOnly.mustRegister(proto.KindTCP, "x", 0)
}

func TestTunnelLimit(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.MaxTunnelsPerClient = 2 })
	// Token limit wins over the server default.
	one := h.login(h.st.newToken(t, "one", func(tk *store.Token) { tk.MaxTunnels = 1 }))
	reg := one.mustRegister(proto.KindHTTP, "a", 0)
	if e := one.registerErr(proto.KindHTTP, "b", 0); e.Code != proto.CodeLimitExceeded {
		t.Errorf("token limit: %+v", e)
	}
	if err := one.write(&proto.Unregister{TunnelID: reg.TunnelID}); err != nil {
		t.Fatal(err)
	}
	// Server default applies to tokens without their own limit. (Retry: unregister is asynchronous.)
	two := h.login(h.st.newToken(t, "two"))
	two.mustRegister(proto.KindHTTP, "a", 0)
	two.mustRegister(proto.KindHTTP, "b", 0)
	if e := two.registerErr(proto.KindTCP, "c", 0); e.Code != proto.CodeLimitExceeded {
		t.Errorf("default limit: %+v", e)
	}
	waitFor(t, "unregister", func() bool { return h.srv.tunnelCount() == 2 })
	one.mustRegister(proto.KindHTTP, "b", 0)
}

func TestUnregisterFreesHostname(t *testing.T) {
	h := newHarness(t)
	backend, _ := recordingBackend(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(forward(backend.Listener.Addr().String()))
	if resp, _ := h.get("web-home.example.test", "/", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if err := c.write(&proto.Unregister{TunnelID: reg.TunnelID}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unregister", func() bool { return h.srv.tunnelCount() == 0 })
	if resp, _ := h.get("web-home.example.test", "/", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("after unregister: status %d, want 404", resp.StatusCode)
	}
	c.mustRegister(proto.KindHTTP, "web", 0)
	if resp, _ := h.get("web-home.example.test", "/", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("after re-register: status %d", resp.StatusCode)
	}
}

func TestClientUnreachable502(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)

	// The client accepts the stream but its local service is down: it closes the stream straight away.
	c.serve(func(_ proto.StreamHeader, st net.Conn) { _ = st.Close() })
	if resp, _ := h.get("web-home.example.test", "/", nil); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("local service down: status %d, want 502", resp.StatusCode)
	}

	// The client disconnects: its hostnames answer 502 (offline), not 404, while it is expected back.
	c.close()
	waitFor(t, "session cleanup", func() bool { return h.srv.sessionCount() == 0 })
	if resp, _ := h.get("web-home.example.test", "/", nil); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("client gone: status %d, want 502", resp.StatusCode)
	}
	if resp, _ := h.get("never-home.example.test", "/", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("never registered: status %d, want 404", resp.StatusCode)
	}

	// The marker expires.
	h.clock.advance(offlineGrace + time.Second)
	if resp, _ := h.get("web-home.example.test", "/", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("after the grace period: status %d, want 404", resp.StatusCode)
	}
}

func TestTCPConnectionLimit(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Limits.MaxConnsPerIP = -1 }) // all connections come from 127.0.0.1
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindTCP, "busy", 0)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	c.serve(func(_ proto.StreamHeader, st net.Conn) { <-hold; _ = st.Close() })
	addr := fmt.Sprintf("127.0.0.1:%d", publicPort(t, reg.PublicURL))

	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	for range maxTCPConnsPerTunnel {
		cn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, cn)
	}
	// Wait until the server has taken all of them, then one more must be dropped.
	waitFor(t, "connections accepted", func() bool {
		h.srv.mu.Lock()
		defer h.srv.mu.Unlock()
		for _, tn := range h.srv.ports {
			return len(tn.sem) == maxTCPConnsPerTunnel
		}
		return false
	})
	extra, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Errorf("connection over the limit: read error %v, want EOF/reset", err)
	}
}

func isReset(err error) bool {
	return err != nil && strings.Contains(err.Error(), "reset")
}

func TestTrustProxyHeaders(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) {
		cfg.TrustProxyHeaders = true
		cfg.TrustedProxies = []string{"127.0.0.0/8", "10.0.0.0/8"} // the test client and the proxy chain
	})
	backend, seen := recordingBackend(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(forward(backend.Listener.Addr().String()))

	h.get("web-home.example.test", "/", http.Header{"X-Forwarded-For": {"203.0.113.7, 10.0.0.1"}})
	got := <-seen
	if v := got.header.Get("X-Forwarded-For"); v != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q, want the right-most address that is not a trusted proxy", v)
	}
	if hdr := <-c.headers; hdr.RemoteAddr != "203.0.113.7:0" {
		t.Errorf("stream remote_addr = %q", hdr.RemoteAddr)
	}
}

func TestVisitorAddr(t *testing.T) {
	var srv *Server
	cases := []struct {
		trust bool
		xff   string
		want  string
	}{
		{false, "1.2.3.4", "9.9.9.9:5555"},
		{true, "", "9.9.9.9:5555"},
		{true, "1.2.3.4", "1.2.3.4:0"},
		{true, "1.2.3.4, 5.6.7.8", "5.6.7.8:0"}, // the proxy appends: the left side is client-controlled
		{true, "2001:db8::1", "[2001:db8::1]:0"},
		{true, "::ffff:1.2.3.4", "1.2.3.4:0"},
		{true, "garbage", "9.9.9.9:5555"},
	}
	for _, tc := range cases {
		srv = newHarness(t, func(cfg *config.Config, _ *Options) { cfg.TrustProxyHeaders = tc.trust }).srv
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "9.9.9.9:5555"
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := srv.visitorAddr(r); got != tc.want {
			t.Errorf("trust=%v xff=%q: got %q, want %q", tc.trust, tc.xff, got, tc.want)
		}
	}
}

func TestValidLabel(t *testing.T) {
	for s, want := range map[string]bool{
		"a": true, "web-home": true, strings.Repeat("a", 63): true,
		"": false, "-a": false, "a-": false, "A": false, "a.b": false, "a_b": false, strings.Repeat("a", 64): false,
	} {
		if got := validLabel(s); got != want {
			t.Errorf("validLabel(%q) = %v, want %v", s, got, want)
		}
	}
}
