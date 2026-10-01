// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

// gwHarness is a harness with a running SSH gateway on a loopback port and a "home" client serving an echo server
// through its ssh tunnel.
type gwHarness struct {
	*harness
	addr    string
	dataDir string
	home    *client
	homeTok testToken
}

func newGW(t *testing.T, mods ...func(*config.Config, *Options)) *gwHarness {
	t.Helper()
	dir := t.TempDir()
	all := append([]func(*config.Config, *Options){func(cfg *config.Config, _ *Options) {
		cfg.SSHGateway.Listen = ":2222"
		cfg.DataDir = dir
	}}, mods...)
	h := newHarness(t, all...)
	return startGW(t, h, dir)
}

func startGW(t *testing.T, h *harness, dir string) *gwHarness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.StartSSHGateway(ln); err != nil {
		t.Fatal(err)
	}
	return &gwHarness{harness: h, addr: ln.Addr().String(), dataDir: dir}
}

// serveHome logs in as client "home" and registers an ssh tunnel (named "" for the default) that reaches echo.
func (g *gwHarness) serveHome(t *testing.T, name string, private bool) {
	t.Helper()
	if g.home == nil {
		g.homeTok = g.st.newToken(t, "home")
		g.home = g.login(g.homeTok)
		g.home.serve(forward(startEcho(t)))
	}
	if _, ok := g.home.registerSSH(name, private).(*proto.Registered); !ok {
		t.Fatal("register ssh tunnel failed")
	}
}

// dial connects to the gateway as user with the given auth methods and checks the host key against the file.
func (g *gwHarness) dial(t *testing.T, user string, methods ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	signer, err := LoadHostKey(g.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ssh.Dial("tcp", g.addr, &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

// roundTrip dials target through c and checks that the echo server answers.
func roundTrip(t *testing.T, c *ssh.Client, target string) error {
	t.Helper()
	conn, err := c.Dial("tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		t.Fatalf("echo %q", buf)
	}
	return nil
}

func TestSSHGatewayPublic(t *testing.T) {
	g := newGW(t)
	g.serveHome(t, "", false)

	c, err := g.dial(t, "alice")
	if err != nil {
		t.Fatalf("none auth refused: %v", err)
	}
	for _, target := range []string{"home:22", "HOME:2200", "home." + testDomain + ":22", "ssh-home:22"} {
		if err := roundTrip(t, c, target); err != nil {
			t.Errorf("%s: %v", target, err)
		}
	}
	hdr := <-g.home.headers
	if host, _, err := net.SplitHostPort(hdr.RemoteAddr); err != nil || host != "127.0.0.1" {
		t.Errorf("stream header remote %q, want the gateway peer 127.0.0.1", hdr.RemoteAddr)
	}

	// Half-close must reach the echo server and the reply must still come back.
	conn, err := c.Dial("tcp", "home:22")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "bye" {
		t.Errorf("after half-close: %q, %v", got, err)
	}
}

func TestSSHGatewayRefusals(t *testing.T) {
	g := newGW(t)
	g.serveHome(t, "", false)
	c, err := g.dial(t, "alice")
	if err != nil {
		t.Fatal(err)
	}

	for _, target := range []string{"nobody:22", "db-home:22", "nas-home:22", "x.other.example:22", "-:22"} {
		err := roundTrip(t, c, target)
		var oce *ssh.OpenChannelError
		if err == nil || !errors.As(err, &oce) || oce.Reason != ssh.ConnectionFailed || oce.Message != "connect failed" {
			t.Errorf("%s: %v, want ConnectionFailed", target, err)
		}
	}
	if s, err := c.NewSession(); err == nil {
		_ = s.Close()
		t.Error("session channel must be refused")
	}
	if ln, err := c.Listen("tcp", "0.0.0.0:0"); err == nil {
		_ = ln.Close()
		t.Error("tcpip-forward must be refused")
	}
	if ok, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil || ok {
		t.Errorf("unknown global request: ok=%v err=%v, want false", ok, err)
	}
	// The connection survives all of that.
	if err := roundTrip(t, c, "home:22"); err != nil {
		t.Errorf("after refusals: %v", err)
	}
}

func TestSSHGatewayPrivate(t *testing.T) {
	g := newGW(t)
	g.serveHome(t, "nas", true)
	g.serveHome(t, "", false)

	connectOK := func(c *ssh.Client, target string) bool { return roundTrip(t, c, target) == nil }

	// No credentials: a none session may not open a private tunnel; the public one next to it is fine.
	anon, err := g.dial(t, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if connectOK(anon, "nas-home:22") {
		t.Error("private tunnel reachable without a token")
	}
	if !connectOK(anon, "home:22") {
		t.Error("public tunnel must stay reachable without a token")
	}
	// The user "token" demands the password.
	if _, err := g.dial(t, "token"); err == nil {
		t.Error("user token without a password must fail")
	}

	own, err := g.dial(t, "token", ssh.Password(g.homeTok.str))
	if err != nil {
		t.Fatalf("own token: %v", err)
	}
	if !connectOK(own, "nas-home:22") || !connectOK(own, "home:22") {
		t.Error("the owner's token must reach the private and the public tunnel")
	}

	other := g.st.newToken(t, "guest")
	guest, err := g.dial(t, "token", ssh.Password(other.str))
	if err != nil {
		t.Fatal(err)
	}
	if connectOK(guest, "nas-home:22") {
		t.Error("a foreign token without connect:home must be refused")
	}
	if !connectOK(guest, "home:22") {
		t.Error("a token session may open public tunnels")
	}

	granted := g.st.newToken(t, "ops", func(tk *store.Token) {
		tk.Scopes = append(tk.Scopes, "connect:home")
	})
	ops, err := g.dial(t, "token", ssh.Password(granted.str))
	if err != nil {
		t.Fatal(err)
	}
	if !connectOK(ops, "nas-home:22") {
		t.Error("connect:home must reach the private tunnel")
	}

	// The token is re-read on every channel: revoking it takes effect inside the open session.
	now := g.clock.Now()
	g.st.update(granted.id, func(tk *store.Token) { tk.RevokedAt = &now })
	if connectOK(ops, "nas-home:22") {
		t.Error("a revoked token must lose access in the running session")
	}
	g.st.update(granted.id, func(tk *store.Token) { tk.RevokedAt = nil; tk.Scopes = auth.DefaultScopes })
	if connectOK(ops, "nas-home:22") {
		t.Error("dropping connect:home must take effect in the running session")
	}

	// Bad passwords never open a session.
	for _, pw := range []string{"", "nonsense", "ph_" + strings.Repeat("a", 40)} {
		if _, err := g.dial(t, "token", ssh.Password(pw)); err == nil {
			t.Errorf("password %q accepted", pw)
		}
	}
}

func TestSSHGatewayFailLimiter(t *testing.T) {
	g := newGW(t)
	g.serveHome(t, "", true)
	blocked := false
	for i := 0; i < failBurst+3 && !blocked; i++ {
		if _, err := g.dial(t, "token", ssh.Password("wrong")); err == nil {
			t.Fatal("wrong password accepted")
		}
		// Once the budget is gone the right token fails too.
		if _, err := g.dial(t, "token", ssh.Password(g.homeTok.str)); err != nil {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("failed logins were never rate limited")
	}
	g.clock.advance(10 * time.Minute)
	if _, err := g.dial(t, "token", ssh.Password(g.homeTok.str)); err != nil {
		t.Errorf("after the limiter window: %v", err)
	}
}

func TestSSHGatewayChannelLimit(t *testing.T) {
	g := newGW(t, func(cfg *config.Config, _ *Options) { cfg.SSHGateway.MaxConnsPerTunnel = 1 })
	g.serveHome(t, "", false)
	c, err := g.dial(t, "alice")
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.Dial("tcp", "home:22")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Dial("tcp", "home:22"); err == nil {
		t.Fatal("second channel must be refused at max_conns_per_tunnel = 1")
	}
	_ = first.Close()
	waitFor(t, "the slot to be released", func() bool { return roundTrip(t, c, "home:22") == nil })
}

func TestSSHGatewayIdleTimeout(t *testing.T) {
	g := newGW(t, func(_ *config.Config, o *Options) { o.SSHIdleTimeout = 200 * time.Millisecond })
	g.serveHome(t, "", false)
	c, err := g.dial(t, "alice")
	if err != nil {
		t.Fatal(err)
	}
	// An open channel keeps the connection alive past the idle timeout.
	conn, err := c.Dial("tcp", "home:22")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("connection with an open channel was closed: %v", err)
	}
	_ = conn.Close()

	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle connection was not closed")
	}
}

func TestSSHGatewayHandshakeTimeout(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, func(cfg *config.Config, o *Options) {
		cfg.SSHGateway.Listen = ":2222"
		cfg.DataDir = dir
		o.HandshakeTimeout = 200 * time.Millisecond
	})
	g := startGW(t, h, dir)
	conn, err := net.Dial("tcp", g.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// The server sends its version line, then waits for ours; silence must get us disconnected.
	_, err = io.ReadAll(conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the gateway did not drop a silent connection")
	}
}

func TestHostKeyPersists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if _, err := HostKeyFingerprint(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fingerprint without a key: %v, want not-exist", err)
	}
	first, err := loadOrCreateHostKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, HostKeyFile))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("host key mode %v, %v; want 0600", fi.Mode(), err)
		}
	}
	second, err := loadOrCreateHostKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	fp1, fp2 := ssh.FingerprintSHA256(first.PublicKey()), ssh.FingerprintSHA256(second.PublicKey())
	if fp1 != fp2 || !strings.HasPrefix(fp1, "SHA256:") {
		t.Errorf("fingerprints %q and %q must match", fp1, fp2)
	}
	if fp, err := HostKeyFingerprint(dir); err != nil || fp != fp1 {
		t.Errorf("HostKeyFingerprint = %q, %v; want %q", fp, err, fp1)
	}
	if err := os.WriteFile(filepath.Join(dir, HostKeyFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateHostKey(dir); err == nil {
		t.Error("a corrupt host key must be an error, not silently replaced")
	}
}
