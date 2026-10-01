// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
)

// registeredHost returns the host name of a registered HTTP tunnel's public URL.
func registeredHost(t *testing.T, reg *proto.Registered) string {
	t.Helper()
	u, err := url.Parse(reg.PublicURL)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("public URL %q: %v", reg.PublicURL, err)
	}
	return u.Hostname()
}

func TestAllowCertName(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	live := registeredHost(t, c.mustRegister(proto.KindHTTP, "web", 0))

	// A tunnel whose client left recently is still inside the offline grace period; an expired one is not.
	h.srv.mu.Lock()
	h.srv.offline["away"] = h.clock.Now().Add(time.Minute)
	h.srv.offline["gone"] = h.clock.Now().Add(-time.Minute)
	h.srv.mu.Unlock()

	tests := []struct {
		name  string
		host  string
		allow bool
	}{
		{"control host", testDomain, true},
		{"control host upper case", "EXAMPLE.test", true},
		{"live tunnel", live, true},
		{"tunnel in offline grace", "away." + testDomain, true},
		{"tunnel past offline grace", "gone." + testDomain, false},
		{"unknown label", "nope." + testDomain, false},
		{"nested name", "a." + live, false},
		{"foreign domain", "web.other.test", false},
		{"suffix lookalike", "web" + testDomain, false},
		{"parent of the domain", "test", false},
		{"ip address", "192.0.2.1", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := h.srv.allowCertName(context.Background(), tc.host)
			if tc.allow && err != nil {
				t.Errorf("refused %q: %v", tc.host, err)
			}
			if !tc.allow && err == nil {
				t.Errorf("allowed %q", tc.host)
			}
		})
	}
}

func TestRedirectHandler(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	live := registeredHost(t, c.mustRegister(proto.KindHTTP, "web", 0))

	tests := []struct {
		name     string
		host     string
		target   string
		status   int
		location string
	}{
		{"control host", testDomain, "/x?y=1", http.StatusMovedPermanently, "https://" + testDomain + "/x?y=1"},
		{"tunnel host with port and case", strings.ToUpper(live) + ":80", "/a/b", http.StatusMovedPermanently, "https://" + live + "/a/b"},
		{"unknown label", "nope." + testDomain, "/", http.StatusNotFound, ""},
		{"foreign host", "evil.example", "/", http.StatusNotFound, ""},
		{"healthz on the domain is not redirected", testDomain, "/healthz", http.StatusOK, ""},
		{"healthz by ip", "192.0.2.1", "/healthz", http.StatusOK, ""},
		{"healthz on a tunnel host belongs to the app", live, "/healthz", http.StatusMovedPermanently, "https://" + live + "/healthz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.srv.redirectHandler().ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			if got := rec.Header().Get("Location"); got != tc.location {
				t.Errorf("Location %q, want %q", got, tc.location)
			}
		})
	}

	// A non-standard public port is kept in the redirect target.
	h.srv.cfg.PublicPort = 8443
	req := httptest.NewRequest(http.MethodGet, "/p", nil)
	req.Host = testDomain
	rec := httptest.NewRecorder()
	h.srv.redirectHandler().ServeHTTP(rec, req)
	if got, want := rec.Header().Get("Location"), "https://"+testDomain+":8443/p"; got != want {
		t.Errorf("Location %q, want %q", got, want)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestACMEModeRefusesUnknownName starts the server in acme mode and checks that a handshake for a name outside
// the registry fails fast: DecisionFunc refuses before any contact with a CA (there is none in this test).
func TestACMEModeRefusesUnknownName(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = testDomain
	cfg.DataDir = t.TempDir()
	cfg.TLS.Mode = config.TLSModeACME
	cfg.TLS.ACME.CA = "https://acme.invalid/directory" // would fail loudly if the server ever tried it
	noHTTP := ""
	cfg.HTTPListen = &noHTTP
	cfg.ShutdownGrace = 2 * time.Second

	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	srv, err := New(Options{Config: cfg, Store: newFakeStore(), Logger: logger, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return")
		}
	})

	for _, name := range []string{"unknown." + testDomain, "a.b." + testDomain, "elsewhere.test"} {
		d := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", ln.Addr().String(), &tls.Config{
			ServerName:         name,
			InsecureSkipVerify: true, //nolint:gosec // the handshake must fail before any certificate is served
		})
		if err == nil {
			_ = conn.Close()
			t.Fatalf("handshake for %q succeeded", name)
		}
	}
	// The server logs the refusal on its side of the handshake, which may finish after the client saw the error.
	logged := func() bool {
		out := logs.String()
		return strings.Contains(out, "certificate refused") && strings.Contains(out, "unknown."+testDomain)
	}
	for deadline := time.Now().Add(2 * time.Second); !logged() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !logged() {
		t.Errorf("refusal not logged with the host name:\n%s", logs.String())
	}
}
