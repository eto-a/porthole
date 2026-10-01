// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/traffic"
)

// waitRequests waits until the request journal holds n entries matching f and returns them, newest first.
func waitRequests(t *testing.T, s *Server, f traffic.RequestFilter, n int) []traffic.Request {
	t.Helper()
	var got []traffic.Request
	waitFor(t, fmt.Sprintf("%d journal requests", n), func() bool {
		got = s.Traffic().Requests().Query(f)
		return len(got) >= n
	})
	return got
}

func waitConns(t *testing.T, s *Server, f traffic.ConnFilter, n int) []traffic.Conn {
	t.Helper()
	var got []traffic.Conn
	waitFor(t, fmt.Sprintf("%d journal connections", n), func() bool {
		got = s.Traffic().Conns().Query(f)
		return len(got) >= n
	})
	return got
}

func TestTrafficHTTPRequest(t *testing.T) {
	h := newHarness(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/teapot" {
			w.WriteHeader(http.StatusTeapot)
		}
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	}))
	t.Cleanup(backend.Close)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(forward(backend.Listener.Addr().String()))

	do := func(method, target, body string) {
		t.Helper()
		req, err := http.NewRequest(method, h.web.URL+target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "web-home.example.test"
		req.Header.Set("User-Agent", "probe/1.0")
		req.Header.Set("Referer", "https://ref.example/a?token=zzz&p=1")
		req.Header.Set("Authorization", "Bearer secret-value")
		req.Header.Set("Cookie", "sid=secret-cookie")
		resp, err := h.httpc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	do(http.MethodPost, "/foo?x=1&api_key=SECRET&password=hunter2", "abcde")
	do(http.MethodGet, "/teapot", "")

	got := waitRequests(t, h.srv, traffic.RequestFilter{}, 2)
	teapot, post := got[0], got[1]
	if post.Method != http.MethodPost || post.Path != "/foo" || post.Status != http.StatusOK || post.BytesIn != 5 || post.BytesOut != int64(len("hello /foo")) {
		t.Errorf("post entry: %+v", post)
	}
	if post.Query != "x=1&api_key=REDACTED&password=REDACTED" {
		t.Errorf("query not masked: %q", post.Query)
	}
	if post.TunnelID != reg.TunnelID || post.Tunnel != "web" || post.Label != "web-home" || post.Client != "home" {
		t.Errorf("tunnel fields: %+v", post)
	}
	if post.VisitorIP != "127.0.0.1" || post.Host != "web-home.example.test" || post.UserAgent != "probe/1.0" {
		t.Errorf("visitor fields: %+v", post)
	}
	if post.Referer != "https://ref.example/a?token=REDACTED&p=1" {
		t.Errorf("referer: %q", post.Referer)
	}
	if post.Latency < 0 || post.Time.IsZero() || post.ID == 0 { // a fast request can take 0 at Windows timer resolution
		t.Errorf("latency/time/id: %+v", post)
	}
	if teapot.Status != http.StatusTeapot || teapot.BytesIn != 0 || teapot.BytesOut != int64(len("hello /teapot")) {
		t.Errorf("teapot entry: %+v", teapot)
	}
	if n := len(h.srv.Traffic().Requests().Query(traffic.RequestFilter{StatusClass: 4})); n != 1 {
		t.Errorf("4xx entries: %d", n)
	}
	dump := fmt.Sprintf("%+v", got)
	for _, secret := range []string{"secret-value", "secret-cookie", "hunter2", "SECRET", "zzz"} {
		if strings.Contains(dump, secret) {
			t.Errorf("journal leaked %q: %s", secret, dump)
		}
	}
}

func TestTrafficHTTPErrorsAndOffline(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(func(_ proto.StreamHeader, st net.Conn) { _ = st.Close() })

	h.get("web-home.example.test", "/down", nil)
	e := waitRequests(t, h.srv, traffic.RequestFilter{}, 1)[0]
	if e.Status != http.StatusBadGateway || e.Path != "/down" || e.Client != "home" || e.BytesOut == 0 {
		t.Errorf("error handler entry: %+v", e)
	}

	c.close()
	waitFor(t, "session cleanup", func() bool { return h.srv.sessionCount() == 0 })
	h.get("web-home.example.test", "/gone", nil)
	e = waitRequests(t, h.srv, traffic.RequestFilter{PathPrefix: "/gone"}, 1)[0]
	if e.Status != http.StatusBadGateway || e.Label != "" || e.Host != "web-home.example.test" {
		t.Errorf("offline entry: %+v", e)
	}

	// Hosts nobody owns are not journaled.
	h.get("never-home.example.test", "/", nil)
	if n := h.srv.Traffic().Requests().Len(); n != 2 {
		t.Errorf("journal has %d entries, want 2", n)
	}
}

func TestTrafficTrustProxyIP(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) {
		cfg.TrustProxyHeaders = true
		cfg.TrustedProxies = []string{"127.0.0.0/8", "10.0.0.0/8"}
	})
	backend, _ := recordingBackend(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(forward(backend.Listener.Addr().String()))

	h.get("web-home.example.test", "/", http.Header{"X-Forwarded-For": {"203.0.113.7, 10.0.0.1"}})
	if e := waitRequests(t, h.srv, traffic.RequestFilter{}, 1)[0]; e.VisitorIP != "203.0.113.7" {
		t.Errorf("visitor ip %q, want the right-most X-Forwarded-For address that is not a trusted proxy", e.VisitorIP)
	}
}

func TestTrafficOff(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Traffic = config.Traffic{} })
	backend, _ := recordingBackend(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(forward(backend.Listener.Addr().String()))

	if resp, body := h.get("web-home.example.test", "/x", nil); resp.StatusCode != http.StatusOK || body != "hello /x" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if h.srv.Traffic() == nil || h.srv.Traffic().Requests().Len() != 0 || h.srv.Traffic().Requests().Enabled() {
		t.Error("a journal sized 0 must stay empty")
	}
}

func TestTrafficWebSocket(t *testing.T) {
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
			if err := conn.Write(r.Context(), typ, data); err != nil {
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
	conn, resp, err := websocket.Dial(ctx, h.web.URL+"/chat", &websocket.DialOptions{Host: "ws-home.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if n := h.srv.Traffic().Requests().Len(); n != 0 {
		t.Errorf("the upgrade is recorded only after the connection closes, have %d entries", n)
	}
	_ = conn.Close(websocket.StatusNormalClosure, "bye")

	e := waitRequests(t, h.srv, traffic.RequestFilter{}, 1)[0]
	if e.Status != http.StatusSwitchingProtocols || e.Path != "/chat" || e.BytesIn == 0 || e.BytesOut == 0 {
		t.Errorf("websocket entry: %+v", e)
	}
}

func TestTrafficTCPConn(t *testing.T) {
	h := newHarness(t)
	echo := startEcho(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindTCP, "echo", 0)
	c.serve(forward(echo))

	_, port, err := net.SplitHostPort(strings.TrimPrefix(reg.PublicURL, "tcp://"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := strings.Repeat("x", 1000)
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	if got, err := io.ReadAll(conn); err != nil || len(got) != len(payload) {
		t.Fatalf("echo %d bytes, %v", len(got), err)
	}

	e := waitConns(t, h.srv, traffic.ConnFilter{Kind: traffic.KindTCP}, 1)[0]
	if e.Outcome != traffic.OutcomeOK || e.BytesIn != 1000 || e.BytesOut != 1000 {
		t.Errorf("tcp entry: %+v", e)
	}
	if e.TunnelID != reg.TunnelID || e.Tunnel != "echo" || e.Client != "home" || e.VisitorIP != "127.0.0.1" || e.Start.IsZero() {
		t.Errorf("tcp entry fields: %+v", e)
	}
}

func TestTrafficSSHGateway(t *testing.T) {
	g := newGW(t)
	g.serveHome(t, "", true)

	// Wrong password: a per-IP auth_failed entry.
	if _, err := g.dial(t, "token", ssh.Password("wrong")); err == nil {
		t.Fatal("wrong password accepted")
	}
	f := waitConns(t, g.srv, traffic.ConnFilter{Outcome: traffic.OutcomeAuthFailed}, 1)[0]
	if f.Kind != traffic.KindSSH || f.VisitorIP != "127.0.0.1" || f.TunnelID != "" {
		t.Errorf("auth failure entry: %+v", f)
	}
	if n := len(g.srv.Traffic().AuthFailures(time.Time{}, 0)); n != 1 {
		t.Errorf("AuthFailures: %d entries", n)
	}

	// A refused target and a successful channel with its bytes.
	good, err := g.dial(t, "token", ssh.Password(g.homeTok.str))
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(t, good, "nobody:22"); err == nil {
		t.Fatal("unknown target reached")
	}
	r := waitConns(t, g.srv, traffic.ConnFilter{Outcome: traffic.OutcomeRefused}, 1)[0]
	if r.Kind != traffic.KindSSH || r.Tunnel != "nobody" || r.VisitorIP != "127.0.0.1" {
		t.Errorf("refused entry: %+v", r)
	}
	if err := roundTrip(t, good, "home:22"); err != nil {
		t.Fatal(err)
	}
	ok := waitConns(t, g.srv, traffic.ConnFilter{Outcome: traffic.OutcomeOK}, 1)[0]
	if ok.Kind != traffic.KindSSH || ok.BytesIn != 4 || ok.BytesOut != 4 || ok.Client != "home" || ok.TunnelID == "" {
		t.Errorf("ok entry: %+v", ok)
	}
}
