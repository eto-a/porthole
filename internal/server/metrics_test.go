// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/metrics"
	"github.com/eto-a/porthole/internal/proto"
)

func withMetrics(m *metrics.Metrics) func(*config.Config, *Options) {
	return func(_ *config.Config, o *Options) { o.Metrics = m }
}

// fetch performs a GET against a local test listener and returns status and body.
func fetch(t *testing.T, url string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func startMetrics(t *testing.T, h *harness) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.StartMetricsListener(ln); err != nil {
		t.Fatal(err)
	}
	return "http://" + ln.Addr().String()
}

func TestMetricsHTTPRequestsAndGauges(t *testing.T) {
	m := metrics.New("test")
	h := newHarness(t, withMetrics(m))
	base := startMetrics(t, h)
	backend, _ := recordingBackend(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)
	c.serve(forward(backend.Listener.Addr().String()))

	if resp, _ := h.get("web-home.example.test", "/x", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp, _ := h.get("nope-home.example.test", "/x", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	h.get("example.test", "/healthz", nil) // the control host is not tunnel traffic

	_, body := fetch(t, base+"/metrics")
	for _, want := range []string{
		`porthole_http_requests_total{status_class="2xx"} 1`,
		`porthole_http_requests_total{status_class="4xx"} 1`,
		"porthole_http_request_duration_seconds_count 2",
		"porthole_sessions 1",
		`porthole_tunnels{kind="http"} 1`,
		`porthole_tunnels{kind="tcp"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
	if got := testutil.CollectAndCount(m.Registry(), "porthole_bytes_total"); got == 0 {
		t.Error("porthole_bytes_total has no series")
	}
	if strings.Contains(body, `porthole_bytes_total{direction="out",kind="http"} 0`) {
		t.Error("response bytes were not counted")
	}
}

func TestMetricsHandshakeFailure(t *testing.T) {
	m := metrics.New("test")
	h := newHarness(t, withMetrics(m))
	base := startMetrics(t, h)
	_ = wantError(t, rawHandshake(t, h.wsURL, goodHello("not-a-token")), proto.CodeUnauthorized, true)
	_, body := fetch(t, base+"/metrics")
	if want := `porthole_handshake_failures_total{reason="unauthorized"} 1`; !strings.Contains(body, want) {
		t.Errorf("/metrics lacks %q", want)
	}
}

func TestMetricsListener(t *testing.T) {
	// metrics_listen in the config makes the server create its own metrics.
	h := newHarness(t, func(c *config.Config, _ *Options) { c.MetricsListen = "127.0.0.1:0" })
	base := startMetrics(t, h)

	status, body := fetch(t, base+"/metrics")
	if status != http.StatusOK || !strings.Contains(body, `porthole_build_info{version="test"} 1`) {
		t.Errorf("/metrics: status %d, build_info missing", status)
	}
	if status, _ := fetch(t, base+"/debug/pprof/cmdline"); status != http.StatusOK {
		t.Errorf("/debug/pprof/cmdline: status %d", status)
	}
	if status, _ := fetch(t, base+"/"); status != http.StatusNotFound {
		t.Errorf("/: status %d, want 404", status)
	}
}

func TestMetricsListenerNeedsMetrics(t *testing.T) {
	h := newHarness(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.StartMetricsListener(ln); err == nil {
		t.Fatal("StartMetricsListener without metrics: want an error")
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:9": true, "[::1]:9": true, "0.0.0.0:9": false, "[::]:9": false, "192.0.2.1:9": false,
	} {
		ta, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := isLoopback(ta); got != want {
			t.Errorf("isLoopback(%s) = %v, want %v", addr, got, want)
		}
	}
}
