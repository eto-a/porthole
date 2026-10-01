// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/transport"
)

func fastRevalidate(_ *config.Config, o *Options) { o.RevalidateInterval = 30 * time.Millisecond }

func TestReplacedSessionFreesEverything(t *testing.T) {
	h := newHarness(t)
	backend, _ := recordingBackend(t)
	tok := h.st.newToken(t, "home")

	old := h.login(tok)
	web := old.mustRegister(proto.KindHTTP, "web", 0)
	tcp := old.mustRegister(proto.KindTCP, "ssh", 0)

	// The same client logs in again. The old session must not block the new login.
	start := time.Now()
	fresh := h.login(tok)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("new login took %v", d)
	}

	// The old session is told and closed.
	e := old.expectFatal(proto.CodeSessionReplaced)
	if !strings.Contains(e.Message, "logged in again") {
		t.Errorf("message %q", e.Message)
	}

	// The new session can immediately reuse the label and gets the reserved port back.
	fresh.serve(forward(backend.Listener.Addr().String()))
	web2 := fresh.mustRegister(proto.KindHTTP, "web", 0)
	tcp2 := fresh.mustRegister(proto.KindTCP, "ssh", 0)
	if web2.PublicURL != web.PublicURL {
		t.Errorf("url changed: %q -> %q", web.PublicURL, web2.PublicURL)
	}
	if publicPort(t, tcp2.PublicURL) != publicPort(t, tcp.PublicURL) {
		t.Errorf("port changed: %q -> %q", tcp.PublicURL, tcp2.PublicURL)
	}
	if resp, body := h.get("web-home.example.test", "/r", nil); resp.StatusCode != http.StatusOK || body != "hello /r" {
		t.Errorf("tunnel of the new session: %d %q", resp.StatusCode, body)
	}
	if h.srv.sessionCount() != 1 {
		t.Errorf("sessions = %d, want 1", h.srv.sessionCount())
	}
}

func TestRevocationClosesLiveSession(t *testing.T) {
	h := newHarness(t, fastRevalidate)
	tok := h.st.newToken(t, "home")
	c := h.login(tok)
	reg := c.mustRegister(proto.KindTCP, "ssh", 0)
	port := publicPort(t, reg.PublicURL)

	h.st.update(tok.id, func(tk *store.Token) { now := time.Now(); tk.RevokedAt = &now })
	_ = c.expectFatal(proto.CodeTokenRevoked)
	waitFor(t, "cleanup", func() bool { return h.srv.sessionCount() == 0 && h.srv.tunnelCount() == 0 })
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		_ = conn.Close()
		t.Error("TCP listener of the revoked session is still open")
	}
	// And it cannot come back.
	if e := wantError(t, rawHandshake(t, h.wsURL, goodHello(tok.str)), proto.CodeTokenRevoked, true); e.Message == "" {
		t.Error("empty message")
	}
}

func TestExpiryClosesLiveSession(t *testing.T) {
	h := newHarness(t, fastRevalidate)
	expires := h.clock.Now().Add(time.Hour)
	c := h.login(h.st.newToken(t, "home", func(tk *store.Token) { tk.ExpiresAt = &expires }))
	c.mustRegister(proto.KindHTTP, "web", 0)
	h.clock.advance(2 * time.Hour)
	_ = c.expectFatal(proto.CodeTokenExpired)
}

func TestRegisterRechecksToken(t *testing.T) {
	// A long revalidation interval: only the check on register can catch the revocation.
	h := newHarness(t)
	tok := h.st.newToken(t, "home")
	c := h.login(tok)
	c.mustRegister(proto.KindHTTP, "web", 0)

	h.st.update(tok.id, func(tk *store.Token) { now := time.Now(); tk.RevokedAt = &now })
	if err := c.write(&proto.Register{ReqID: 99, Kind: proto.KindHTTP, Name: "late"}); err != nil {
		t.Fatal(err)
	}
	e := c.expectFatal(proto.CodeTokenRevoked)
	if e.ReqID != 99 {
		t.Errorf("req_id = %d, want 99", e.ReqID)
	}

	// Scope removed: the register is refused (non-fatal) based on the freshly read token.
	tok2 := h.st.newToken(t, "other")
	c2 := h.login(tok2)
	h.st.update(tok2.id, func(tk *store.Token) { tk.Scopes = []string{auth.ScopeTunnelTCP} })
	if e := c2.registerErr(proto.KindHTTP, "web", 0); e.Code != proto.CodeForbidden {
		t.Errorf("got %+v, want forbidden", e)
	}
}

func TestScopeRemovalClosesTunnels(t *testing.T) {
	h := newHarness(t, fastRevalidate)
	tok := h.st.newToken(t, "home")
	c := h.login(tok)
	tcp := c.mustRegister(proto.KindTCP, "ssh", 0)
	web := c.mustRegister(proto.KindHTTP, "web", 0)

	h.st.update(tok.id, func(tk *store.Token) { tk.Scopes = []string{auth.ScopeTunnelHTTP} })
	m, ok := c.next().(*proto.TunnelClosed)
	if !ok || m.TunnelID != tcp.TunnelID {
		t.Fatalf("got %#v, want tunnel_closed for the tcp tunnel", m)
	}
	waitFor(t, "tcp tunnel gone", func() bool { return h.srv.tunnelCount() == 1 })
	_ = web
	select {
	case <-c.done:
		t.Error("session was closed, only the tunnel should be")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestStoreFailureDoesNotKillSessions(t *testing.T) {
	h := newHarness(t, fastRevalidate)
	tok := h.st.newToken(t, "home")
	c := h.login(tok)

	h.st.failGet.Store(true)
	if e := c.registerErr(proto.KindHTTP, "web", 0); e.Code != proto.CodeInternal {
		t.Errorf("register during a store failure: %+v, want internal", e)
	}
	time.Sleep(150 * time.Millisecond) // several failed revalidations
	select {
	case <-c.done:
		t.Fatal("a transient store failure closed the session")
	default:
	}
	h.st.failGet.Store(false)
	c.mustRegister(proto.KindHTTP, "web", 0)
}

func TestHeartbeatMissedPongsCloseSession(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.HeartbeatInterval = 30 * time.Millisecond })
	c := h.login(h.st.newToken(t, "home"))
	c.noPong.Store(true)
	c.waitClosed()
	if n := c.pings.Load(); n < maxMissedPongs {
		t.Errorf("session closed after %d pings, want at least %d", n, maxMissedPongs)
	}
	waitFor(t, "cleanup", func() bool { return h.srv.sessionCount() == 0 })
}

func TestHeartbeatKeepsAnsweringClientAlive(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.HeartbeatInterval = 20 * time.Millisecond })
	c := h.login(h.st.newToken(t, "home"))
	time.Sleep(300 * time.Millisecond)
	select {
	case <-c.done:
		t.Fatal("a client that answers pings was disconnected")
	default:
	}
	if n := c.pings.Load(); n < 5 {
		t.Errorf("only %d pings in 300ms with a 20ms interval", n)
	}
	c.mustRegister(proto.KindHTTP, "web", 0)
}

// ---- Serve / Run / TLS -----------------------------------------------------------------------------------------

// standalone builds a Server on the loopback address itself (domain 127.0.0.1) so that the real
// transport.DialWebSocket reaches the control endpoint without any Host shim.
func standalone(t *testing.T, mod func(*config.Config)) (*Server, *fakeStore, *config.Config) {
	t.Helper()
	lo, hi := freePortRange(t)
	cfg := config.Default()
	cfg.Domain = "127.0.0.1"
	cfg.TCPBindHost = "127.0.0.1"
	cfg.TCPPortRange = fmt.Sprintf("%d-%d", lo, hi)
	cfg.DataDir = "unused"
	cfg.TLS.Mode = config.TLSModeOff
	cfg.ShutdownGrace = 2 * time.Second
	if mod != nil {
		mod(cfg)
	}
	st := newFakeStore()
	srv, err := New(Options{Config: cfg, Store: st, Logger: quietLogger(), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, st, cfg
}

func TestServeGracefulShutdown(t *testing.T) {
	srv, st, _ := standalone(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	addr := ln.Addr().String()
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := hc.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}

	tok := st.newToken(t, "home")
	c := loginAt(t, "ws://"+addr+proto.ConnectPath, tok.str, transport.DialOptions{})
	reg := c.mustRegister(proto.KindTCP, "ssh", 0)
	port := publicPort(t, reg.PublicURL)

	cancel()
	_ = c.expectFatal(proto.CodeShuttingDown)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v, want nil after a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
	for _, a := range []string{addr, fmt.Sprintf("127.0.0.1:%d", port)} {
		if conn, err := net.DialTimeout("tcp", a, 500*time.Millisecond); err == nil {
			_ = conn.Close()
			t.Errorf("%s still accepts connections after shutdown", a)
		}
	}
	// A closed server refuses further work.
	if srv.start(func() {}) {
		t.Error("closed server accepted a new goroutine")
	}
}

func TestRunListenFailure(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	srv, _, _ := standalone(t, func(c *config.Config) { c.Listen = busy.Addr().String() })
	if err := srv.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("Run on a busy address: %v", err)
	}
}

func TestRunServesAndStops(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	srv, _, _ := standalone(t, func(c *config.Config) { c.Listen = addr })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	hc := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	waitFor(t, "healthz", func() bool {
		resp, err := hc.Get("http://" + addr + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestTLSListenerAndWSS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSigned(t, dir)
	srv, st, cfg := standalone(t, func(c *config.Config) {
		c.TLS = config.TLS{CertFile: certFile, KeyFile: keyFile}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	if !cfg.TLS.Enabled() {
		t.Fatal("TLS not enabled in config")
	}

	insecure := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed test certificate
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: insecure}}
	addr := ln.Addr().String()
	resp, err := hc.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 1 {
		t.Errorf("healthz over TLS: %d HTTP/%d", resp.StatusCode, resp.ProtoMajor)
	}

	c := loginAt(t, "wss://"+addr+proto.ConnectPath, st.newToken(t, "home").str, transport.DialOptions{TLSConfig: insecure})
	c.mustRegister(proto.KindHTTP, "web", 0)
}

func TestTLSMissingFiles(t *testing.T) {
	srv, _, _ := standalone(t, func(c *config.Config) {
		c.TLS = config.TLS{CertFile: filepath.Join(t.TempDir(), "nope.pem"), KeyFile: filepath.Join(t.TempDir(), "nope.key")}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Serve(context.Background(), ln); err == nil {
		t.Error("Serve with unreadable certificate files returned nil")
	}
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSigned(t, dir)
	clock := newFakeClock()
	cr, err := newCertReloader(certFile, keyFile, quietLogger(), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := cr.get(nil)

	// Replace the files (newer mtime) but stay within the check interval: the old certificate is served.
	writeSelfSigned(t, dir)
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(certFile, future, future)
	if got, _ := cr.get(nil); got != first {
		t.Error("certificate was reloaded before the check interval elapsed")
	}
	clock.advance(certCheckInterval + time.Second)
	if got, _ := cr.get(nil); got == first {
		t.Error("renewed certificate was not picked up")
	}
	// A broken replacement keeps the previous certificate.
	good, _ := cr.get(nil)
	if err := os.WriteFile(certFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := future.Add(time.Hour)
	_ = os.Chtimes(certFile, later, later)
	clock.advance(certCheckInterval + time.Second)
	if got, _ := cr.get(nil); got != good {
		t.Error("a broken certificate file replaced the working one")
	}
}

func TestNewValidation(t *testing.T) {
	st := newFakeStore()
	if _, err := New(Options{Store: st}); err == nil {
		t.Error("New without Config succeeded")
	}
	if _, err := New(Options{Config: config.Default()}); err == nil {
		t.Error("New without Store succeeded")
	}
	if _, err := New(Options{Config: config.Default(), Store: st}); err == nil {
		t.Error("New with an invalid config (no domain) succeeded")
	}
}

func writeSelfSigned(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
