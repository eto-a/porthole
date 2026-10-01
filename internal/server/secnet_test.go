// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/transport"
)

// P-1: an unauthenticated peer must not be able to make the server buffer megabytes in extra yamux streams.
func TestPreAuthStreamFlood(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.HandshakeTimeout = 30 * time.Second })
	ts, ctrl := dialSession(t, h.wsURL, transport.DialOptions{})
	defer ts.Close()
	_ = ctrl // control stream opened, never says hello

	chunk := make([]byte, 256<<10)
	var wg sync.WaitGroup
	for range 16 {
		st, err := ts.Open()
		if err != nil {
			break
		}
		wg.Go(func() {
			_ = st.SetWriteDeadline(time.Now().Add(3 * time.Second))
			_, _ = st.Write(chunk)
		})
	}
	defer wg.Wait()
	select {
	case <-ts.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the server kept a session that pushed 4 MiB into extra streams before authenticating")
	}
}

// P-2: pending (not yet authenticated) sessions are limited per IP, and silence counts as a failure.
func TestPendingHandshakeLimit(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.HandshakeTimeout = 30 * time.Second })
	var sessions []transport.Session
	t.Cleanup(func() {
		for _, s := range sessions {
			_ = s.Close()
		}
	})
	ok := 0
	for range 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ts, err := transport.DialWebSocket(ctx, h.wsURL, transport.DialOptions{})
		cancel()
		if err == nil {
			ok++
			sessions = append(sessions, ts)
		}
	}
	if ok > maxPendingPerIP {
		t.Errorf("%d concurrent unauthenticated sessions from one IP, want at most %d", ok, maxPendingPerIP)
	}
}

// A1/N-03/P-4: X-Forwarded-For is trusted only from trusted proxies, taking the right-most untrusted hop.
func TestVisitorAddrTrustedProxies(t *testing.T) {
	cases := []struct {
		name    string
		trust   bool
		proxies []string
		peer    string
		xff     []string
		want    string
	}{
		{"off", false, nil, "9.9.9.9:1", []string{"1.2.3.4"}, "9.9.9.9:1"},
		{"no list takes the last hop", true, nil, "9.9.9.9:1", []string{"6.6.6.6, 1.2.3.4"}, "1.2.3.4:0"},
		{"no list, several header lines", true, nil, "9.9.9.9:1", []string{"6.6.6.6", "1.2.3.4"}, "1.2.3.4:0"},
		{"untrusted peer is ignored", true, []string{"10.0.0.0/8"}, "9.9.9.9:1", []string{"1.2.3.4"}, "9.9.9.9:1"},
		{"spoofed left entry", true, []string{"10.0.0.0/8"}, "10.0.0.1:1", []string{"6.6.6.6, 1.2.3.4"}, "1.2.3.4:0"},
		{"trusted hops are skipped", true, []string{"10.0.0.0/8"}, "10.0.0.1:1", []string{"1.2.3.4, 10.0.0.9"}, "1.2.3.4:0"},
		{"all hops trusted", true, []string{"10.0.0.0/8"}, "10.0.0.1:1", []string{"10.0.0.5, 10.0.0.9"}, "10.0.0.5:0"},
		{"garbage last hop", true, []string{"10.0.0.0/8"}, "10.0.0.1:1", []string{"1.2.3.4, garbage"}, "10.0.0.1:1"},
		{"no header", true, []string{"10.0.0.0/8"}, "10.0.0.1:1", nil, "10.0.0.1:1"},
		{"v4-mapped", true, nil, "9.9.9.9:1", []string{"::ffff:1.2.3.4"}, "1.2.3.4:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(cfg *config.Config, _ *Options) {
				cfg.TrustProxyHeaders = tc.trust
				cfg.TrustedProxies = tc.proxies
			})
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.peer
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := h.srv.visitorAddr(r); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// N-01: while a client is offline its label stays reserved for it; another client cannot take it.
func TestOfflineLabelReservedForOwner(t *testing.T) {
	h := newHarness(t)
	owner := h.login(h.st.newToken(t, "x-b"))
	owner.mustRegister(proto.KindHTTP, "a", 0) // label a-x-b
	owner.close()
	waitFor(t, "owner gone", func() bool { return h.srv.sessionCount() == 0 })

	squatter := h.login(h.st.newToken(t, "b"))
	if e := squatter.registerErr(proto.KindHTTP, "a-x", 0); e.Code != proto.CodeNameTaken { // also a-x-b
		t.Fatalf("squatting an offline label: %+v, want name_taken", e)
	}
	// The owner gets it back, and after the grace period the label is free again.
	back := h.login(h.st.newToken(t, "x-b"))
	back.mustRegister(proto.KindHTTP, "a", 0)
	back.close()
	waitFor(t, "owner gone again", func() bool { return h.srv.sessionCount() == 1 })
	h.clock.advance(offlineGrace + time.Second)
	// The grace period only covers the reconnect; the label itself is claimed for good (label_claims), so the
	// squatter stays out until the operator releases it.
	if e := squatter.registerErr(proto.KindHTTP, "a-x", 0); e.Code != proto.CodeNameTaken {
		t.Fatalf("squatting after the grace period: %+v, want name_taken", e)
	}
	if err := h.st.ReleaseLabel(context.Background(), "a-x-b"); err != nil {
		t.Fatal(err)
	}
	squatter.mustRegister(proto.KindHTTP, "a-x", 0)
}

func TestLookupSSHExactLabels(t *testing.T) {
	h := newHarness(t, withGateway)
	xb := h.login(h.st.newToken(t, "x-b"))
	reg := xb.registerSSH("a", false).(*proto.Registered) // label a-x-b
	b := h.login(h.st.newToken(t, "b"))
	if e, ok := b.registerSSH("a-x", false).(*proto.Error); !ok || e.Code != proto.CodeNameTaken {
		t.Fatalf("ambiguous ssh label accepted: %+v", e)
	}
	tun, ok := h.srv.lookupSSH("a-x-b")
	if !ok || tun.id != reg.TunnelID {
		t.Fatalf("a-x-b resolved to %v, %v", tun, ok)
	}
	// While x-b is offline the label stays reserved; b cannot take over the address.
	xb.close()
	waitFor(t, "x-b gone", func() bool { return h.srv.sessionCount() == 1 })
	if e, ok := b.registerSSH("a-x", false).(*proto.Error); !ok || e.Code != proto.CodeNameTaken {
		t.Fatalf("offline ssh label taken over: %+v", e)
	}
	if _, ok := h.srv.lookupSSH("a-x-b"); ok {
		t.Error("an offline tunnel must not resolve")
	}
}

// N-02: churning through new host names must run into the issuance budget; names that already have a certificate
// are free.
func TestACMEIssuanceBudget(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) {
		cfg.MaxTunnelsPerClient = 100
		cfg.TLS.ACME.MaxNewNamesPerDay = 1000
	})
	c := h.login(h.st.newToken(t, "home"))
	allowed := 0
	for i := range 25 {
		reg := c.mustRegister(proto.KindHTTP, fmt.Sprintf("t%d", i), 0)
		host := registeredHost(t, reg)
		if h.srv.allowCertName(context.Background(), host) == nil {
			allowed++
		}
		if err := c.write(&proto.Unregister{TunnelID: reg.TunnelID}); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "unregister", func() bool { return h.srv.tunnelCount() == 0 })
	}
	if allowed != maxNewNamesPerClientPerHour {
		t.Fatalf("%d new names allowed for one client within an hour, want %d", allowed, maxNewNamesPerClientPerHour)
	}
	// The same name again is not charged twice.
	reg := c.mustRegister(proto.KindHTTP, "t0", 0)
	if err := h.srv.allowCertName(context.Background(), registeredHost(t, reg)); err != nil {
		t.Errorf("a name charged before is refused again: %v", err)
	}
	// A name with a stored certificate does not spend budget.
	h.srv.certBudget.exists = func(context.Context, string) bool { return true }
	reg = c.mustRegister(proto.KindHTTP, "fresh", 0)
	if err := h.srv.allowCertName(context.Background(), registeredHost(t, reg)); err != nil {
		t.Errorf("name with an existing certificate refused: %v", err)
	}
	// Another client has its own budget, but the global per-day budget is shared.
	h.srv.certBudget.exists = nil
	h.cfg.TLS.ACME.MaxNewNamesPerDay = 3
	h.srv.certBudget.maxPerDay = 3
	other := h.login(h.st.newToken(t, "other"))
	n := 0
	for i := range 6 {
		reg := other.mustRegister(proto.KindHTTP, fmt.Sprintf("o%d", i), 0)
		if h.srv.allowCertName(context.Background(), registeredHost(t, reg)) == nil {
			n++
		}
	}
	if n != 0 { // the first client already spent far more than 3 today
		t.Errorf("global budget not enforced: %d names allowed after the daily budget was spent", n)
	}
}

// P-7: the result of a remote open is taken from the registry, not from the client's claim.
func TestRemoteOpenResultVerified(t *testing.T) {
	h := newHarness(t)
	be := adminBackend{h.srv}
	c := h.loginRemote("home")

	ask := func() (adminapi.RemoteTunnel, error) {
		done := make(chan struct {
			tun adminapi.RemoteTunnel
			err error
		}, 1)
		go func() {
			tun, err := be.RequestTunnel(context.Background(), "home", adminapi.RemoteOpen{Kind: proto.KindHTTP, LocalAddr: "3000", Name: "web"})
			done <- struct {
				tun adminapi.RemoteTunnel
				err error
			}{tun, err}
		}()
		req := c.next().(*proto.OpenRequest)
		if err := c.write(&proto.OpenResult{ReqID: req.ReqID, OK: true, Tunnel: &proto.OpenedTunnel{
			Name: "web", Kind: proto.KindHTTP, PublicURL: "https://attacker.example/login",
		}}); err != nil {
			t.Fatal(err)
		}
		r := <-done
		return r.tun, r.err
	}
	// Nothing registered: a claimed success is an error.
	if _, err := ask(); err == nil {
		t.Fatal("success without a registered tunnel was passed on")
	}
	// Registered: the URL comes from the registry.
	c.mustRegister(proto.KindHTTP, "web", 0)
	tun, err := ask()
	if err != nil {
		t.Fatal(err)
	}
	if tun.URL != "https://web-home."+testDomain {
		t.Errorf("URL %q taken from the client, want the registry's https://web-home.%s", tun.URL, testDomain)
	}
}

// N-04: one IP cannot hold more than maxConnsPerIP connections of a TCP tunnel.
func TestTCPPerIPLimit(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindTCP, "busy", 0)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	c.serve(func(_ proto.StreamHeader, st net.Conn) { <-hold; _ = st.Close() })
	addr := fmt.Sprintf("127.0.0.1:%d", publicPort(t, reg.PublicURL))

	var conns []net.Conn
	t.Cleanup(func() {
		for _, cn := range conns {
			_ = cn.Close()
		}
	})
	for range defaultMaxConnsPerIP + 8 {
		cn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, cn)
	}
	waitFor(t, "connections settled", func() bool {
		h.srv.mu.Lock()
		defer h.srv.mu.Unlock()
		for _, tn := range h.srv.ports {
			return len(tn.sem) >= defaultMaxConnsPerIP
		}
		return false
	})
	time.Sleep(100 * time.Millisecond)
	h.srv.mu.Lock()
	var held int
	for _, tn := range h.srv.ports {
		held = len(tn.sem)
	}
	h.srv.mu.Unlock()
	if held != defaultMaxConnsPerIP {
		t.Errorf("one IP holds %d connections of a tunnel, want %d", held, defaultMaxConnsPerIP)
	}
}

// N-04: a piped connection without traffic in either direction is closed after the idle timeout.
func TestTCPIdleTimeout(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Limits.TCPIdleTimeout = 300 * time.Millisecond })
	echo := startEcho(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindTCP, "echo", 0)
	c.serve(forward(echo))
	cn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort(t, reg.PublicURL)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cn.Close()
	// Traffic keeps it alive well beyond the timeout...
	for range 6 {
		_, _ = cn.Write([]byte("x"))
		_ = cn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := cn.Read(make([]byte, 1)); err != nil {
			t.Fatalf("connection with traffic was closed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// ...and silence ends it.
	_ = cn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := cn.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("idle connection was not closed (read error: %v)", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// N-04: the number of simultaneous requests per HTTP tunnel is bounded.
func TestHTTPConcurrencyLimit(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Limits.MaxHTTPRequestsPerTunnel = 2 })
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	c.serve(func(_ proto.StreamHeader, st net.Conn) { <-hold; _ = st.Close() })

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { _, _ = h.get2("web-home.example.test", "/slow") })
	}
	t.Cleanup(wg.Wait)
	time.Sleep(300 * time.Millisecond)
	resp, err := h.get2("web-home.example.test", "/third")
	if err != nil {
		t.Fatal(err)
	}
	if resp != http.StatusServiceUnavailable {
		t.Errorf("third concurrent request: status %d, want 503", resp)
	}
}

// get2 is get without failing the test on transport errors; it returns the status code.
func (h *harness) get2(host, path string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, h.web.URL+path, nil)
	if err != nil {
		return 0, err
	}
	req.Host = host
	resp, err := h.httpc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

var _ = auth.ValidName

// N-04: a request body that stalls is aborted instead of holding the tunnel's stream forever; a steady upload is
// not affected.
func TestHTTPBodyStall(t *testing.T) {
	stalled := func(t *testing.T, idle time.Duration) bool {
		h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Limits.HTTPBodyIdleTimeout = idle })
		c := h.login(h.st.newToken(t, "home"))
		c.mustRegister(proto.KindHTTP, "web", 0)
		hold := make(chan struct{})
		t.Cleanup(func() { close(hold) })
		c.serve(func(_ proto.StreamHeader, st net.Conn) { <-hold; _ = st.Close() }) // a backend that waits for the whole body

		cn, err := net.Dial("tcp", h.web.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer cn.Close()
		fmt.Fprintf(cn, "POST /up HTTP/1.1\r\nHost: web-home.example.test\r\nContent-Length: 100\r\n\r\nabcde")
		_ = cn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 64)
		n, err := cn.Read(buf)
		return n > 0 || (err != nil && !isTimeout(err)) // an answer (or a closed connection) arrived: the stall was cut off
	}
	if !stalled(t, 300*time.Millisecond) {
		t.Error("a stalled request body was not aborted")
	}
	if stalled(t, -1) {
		t.Error("with the limit off the stalled body should hang (control case)")
	}
}

// A connection that one side has half-closed is cut after limits.tcp_half_close_timeout even when the general idle
// limit is off (limits.tcp_idle_timeout: -1): the two limits are independent.
func TestTCPHalfCloseTimeoutIndependentOfIdle(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) {
		cfg.Limits.TCPIdleTimeout = -1
		cfg.Limits.TCPHalfCloseTimeout = 300 * time.Millisecond
	})
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindTCP, "half", 0)
	// The service closes its write side at once and then says nothing, but keeps reading.
	c.serve(func(_ proto.StreamHeader, st net.Conn) {
		_ = st.Close()
		_, _ = io.Copy(io.Discard, st)
	})
	cn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort(t, reg.PublicURL)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cn.Close()

	h.srv.mu.Lock()
	var tun *tunnel
	for _, x := range h.srv.ports {
		tun = x
	}
	h.srv.mu.Unlock()
	if tun == nil {
		t.Fatal("no tunnel")
	}
	waitFor(t, "connection taken", func() bool { return len(tun.sem) == 1 })
	deadline := time.Now().Add(3 * time.Second)
	for len(tun.sem) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a half-closed connection outlived tcp_half_close_timeout with the idle limit off")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
