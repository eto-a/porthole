// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/traffic"
)

func tcpAddr(t *testing.T, s string) *net.TCPAddr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// proxyHeader builds a PROXY header of the given version (1 or 2) announcing src as the visitor.
func proxyHeader(t *testing.T, version byte, src string) []byte {
	t.Helper()
	b, err := proxyproto.HeaderProxyFromAddrs(version, tcpAddr(t, src), tcpAddr(t, "192.0.2.1:443")).Format()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rawHTTP sends prefix followed by a bare HTTP request and returns the response body, or "" when the server
// closed the connection without answering.
func rawHTTP(t *testing.T, addr, host string, prefix []byte) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(append(append([]byte{}, prefix...), "GET / HTTP/1.0\r\nHost: "+host+"\r\n\r\n"...)); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	_, body, _ := strings.Cut(string(b), "\r\n\r\n")
	return body
}

func TestProxyProtocolListener(t *testing.T) {
	serve := func(trusted ...string) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		pl, err := wrapProxyProtocol(ln, trusted)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{
			Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.RemoteAddr) }),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() { _ = srv.Serve(pl) }()
		t.Cleanup(func() { _ = srv.Close() })
		return ln.Addr().String()
	}

	// The test peer is 127.0.0.1.
	trusted := serve("127.0.0.1")
	untrusted := serve("10.0.0.0/8")

	for _, tc := range []struct {
		name, addr string
		prefix     []byte
		want       string // exact body; "" = no answer
		wantPrefix string
	}{
		{name: "trusted v1", addr: trusted, prefix: proxyHeader(t, 1, "203.0.113.7:4321"), want: "203.0.113.7:4321"},
		{name: "trusted v2", addr: trusted, prefix: proxyHeader(t, 2, "203.0.113.8:4322"), want: "203.0.113.8:4322"},
		{name: "trusted v2 ipv6", addr: trusted, prefix: proxyHeader(t, 2, "[2001:db8::5]:4323"), want: "[2001:db8::5]:4323"},
		{name: "trusted without header", addr: trusted, want: ""},
		{name: "untrusted with header", addr: untrusted, prefix: proxyHeader(t, 2, "203.0.113.9:1"), want: ""},
		{name: "untrusted without header", addr: untrusted, wantPrefix: "127.0.0.1:"},
	} {
		got := rawHTTP(t, tc.addr, "x", tc.prefix)
		switch {
		case tc.wantPrefix != "":
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("%s: got %q, want prefix %q", tc.name, got, tc.wantPrefix)
			}
		case got != tc.want:
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := wrapProxyProtocol(ln, []string{"nonsense"}); err == nil {
		t.Error("invalid trusted entry accepted")
	}
}

func TestProxyProtocolOff(t *testing.T) {
	h := newHarness(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	same, err := h.srv.wrapProxyIf(ln, h.cfg.ProxyProtocol)
	if err != nil || same != ln {
		t.Fatalf("listener wrapped although proxy_protocol is off: %v %v", same, err)
	}
	_ = ln.Close()
}

// TestProxyProtocolRequestJournal serves the visitor handler on a PROXY-aware listener (as Serve does) and checks
// that the request journal records the address from the header.
func TestProxyProtocolRequestJournal(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) {
		cfg.ProxyProtocol = true
		cfg.TrustedProxies = []string{"127.0.0.1"}
	})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(backend.Close)
	c := h.login(h.st.newToken(t, "home"))
	c.serve(forward(backend.Listener.Addr().String()))
	c.mustRegister(proto.KindHTTP, "web", 0)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl, err := h.srv.wrapProxyIf(ln, h.cfg.ProxyProtocol)
	if err != nil {
		t.Fatal(err)
	}
	front := &http.Server{Handler: h.srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = front.Serve(pl) }()
	t.Cleanup(func() { _ = front.Close() })

	for i, v := range []byte{1, 2} {
		src := fmt.Sprintf("203.0.113.%d:5000", 10+i)
		if body := rawHTTP(t, ln.Addr().String(), "web-home.example.test", proxyHeader(t, v, src)); body != "ok" {
			t.Fatalf("v%d: tunnel answered %q", v, body)
		}
	}
	if body := rawHTTP(t, ln.Addr().String(), "web-home.example.test", nil); body != "" {
		t.Fatalf("a request without the mandatory header got %q", body)
	}
	got := waitRequests(t, h.srv, traffic.RequestFilter{}, 2)
	seen := map[string]bool{got[0].VisitorIP: true, got[1].VisitorIP: true}
	if !seen["203.0.113.10"] || !seen["203.0.113.11"] {
		t.Errorf("journal visitors %q, %q, want the PROXY header addresses", got[0].VisitorIP, got[1].VisitorIP)
	}
}

func TestProxyProtocolSSHGateway(t *testing.T) {
	g := newGW(t, func(cfg *config.Config, _ *Options) {
		cfg.ProxyProtocol = true
		cfg.ProxyProtocolSSH = true
		cfg.TrustedProxies = []string{"127.0.0.1"}
	})
	g.serveHome(t, "", true)

	login := func(src, password string) error {
		raw, err := net.DialTimeout("tcp", g.addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if src != "" {
			if _, err := raw.Write(proxyHeader(t, 2, src)); err != nil {
				t.Fatal(err)
			}
		}
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		cc, chans, reqs, err := ssh.NewClientConn(raw, g.addr, &ssh.ClientConfig{
			User:            "token",
			Auth:            []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test: the host key is not under test
		})
		if err != nil {
			_ = raw.Close()
			return err
		}
		_ = raw.SetDeadline(time.Time{})
		go ssh.DiscardRequests(reqs)
		go func() {
			for nc := range chans {
				_ = nc.Reject(ssh.Prohibited, "")
			}
		}()
		t.Cleanup(func() { _ = cc.Close() })
		return nil
	}

	// Exhaust the failure budget of one visitor address...
	for i := 0; i < failBurst+3; i++ {
		_ = login("198.51.100.1:7000", "wrong")
	}
	if err := login("198.51.100.1:7001", g.homeTok.str); err == nil {
		t.Fatal("the limited visitor logged in")
	}
	// ...while a second visitor behind the same proxy is unaffected; the proxy itself must always send a header.
	if err := login("198.51.100.2:7000", g.homeTok.str); err != nil {
		t.Fatalf("another visitor was limited too: %v", err)
	}
	if err := login("", g.homeTok.str); err == nil {
		t.Fatal("a trusted proxy without a PROXY header was served")
	}
}

// TestProxyProtocolSSHOff: proxy_protocol alone leaves the SSH gateway unwrapped, so a trusted-proxy address that
// sends no header is served normally.
func TestProxyProtocolSSHOff(t *testing.T) {
	g := newGW(t, func(cfg *config.Config, _ *Options) {
		cfg.ProxyProtocol = true
		cfg.TrustedProxies = []string{"127.0.0.1"}
	})
	g.serveHome(t, "", true)

	raw, err := net.DialTimeout("tcp", g.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	cc, chans, reqs, err := ssh.NewClientConn(raw, g.addr, &ssh.ClientConfig{
		User:            "token",
		Auth:            []ssh.AuthMethod{ssh.Password(g.homeTok.str)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test: the host key is not under test
	})
	if err != nil {
		_ = raw.Close()
		t.Fatalf("gateway refused a plain connection although proxy_protocol_ssh is off: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "")
		}
	}()
	t.Cleanup(func() { _ = cc.Close() })
}
