// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"testing"

	"github.com/eto-a/porthole/internal/proto"
)

// TestHealthzRouting covers the /healthz routing table: it answers on the bare domain and on every Host outside
// the domain (load balancers probe by IP), but on <label>.<domain> the path belongs to the tunnelled application.
func TestHealthzRouting(t *testing.T) {
	h := newHarness(t)
	backend, _ := recordingBackend(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(forward(backend.Listener.Addr().String()))

	tests := []struct {
		name   string
		host   string
		path   string
		status int
		body   string
	}{
		{"bare domain", "example.test", "/healthz", http.StatusOK, "ok"},
		{"bare domain with port and case", "EXAMPLE.test:443", "/healthz", http.StatusOK, "ok"},
		{"bare domain, trailing dot", "example.test.", "/healthz", http.StatusOK, "ok"},
		{"IPv4", "192.0.2.10", "/healthz", http.StatusOK, "ok"},
		{"IPv4 with port", "192.0.2.10:8443", "/healthz", http.StatusOK, "ok"},
		{"IPv6 with port", "[2001:db8::1]:443", "/healthz", http.StatusOK, "ok"},
		{"IPv6 without port", "[::1]", "/healthz", http.StatusOK, "ok"},
		{"foreign domain", "other.test", "/healthz", http.StatusOK, "ok"},
		{"domain only as a prefix", "example.test.evil.test", "/healthz", http.StatusOK, "ok"},
		{"suffix without a dot", "notexample.test", "/healthz", http.StatusOK, "ok"},
		{"live tunnel is the app's business", "web-home.example.test", "/healthz", http.StatusOK, "hello /healthz"},
		{"unknown label", "nope-home.example.test", "/healthz", http.StatusNotFound, ""},
		{"two labels under the domain", "a.web-home.example.test", "/healthz", http.StatusNotFound, ""},
		{"IPv4, other path", "192.0.2.10", "/", http.StatusNotFound, ""},
		{"IPv4, healthz subpath", "192.0.2.10", "/healthz/x", http.StatusNotFound, ""},
		{"bare domain, other path", "example.test", "/", http.StatusNotFound, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := h.get(tc.host, tc.path, nil)
			if resp.StatusCode != tc.status {
				t.Fatalf("GET %s (Host %q): status %d, want %d", tc.path, tc.host, resp.StatusCode, tc.status)
			}
			if tc.body != "" && body != tc.body {
				t.Errorf("GET %s (Host %q): body %q, want %q", tc.path, tc.host, body, tc.body)
			}
		})
	}
}
