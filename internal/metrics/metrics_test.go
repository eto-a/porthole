// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNilMetricsIsSafe(t *testing.T) {
	var m *Metrics
	m.SetStateSource(nil)
	m.HandshakeFailed("x")
	m.SSHAuthFailed()
	m.ConnOutcome(KindTCP, OutcomeAccepted)
	m.AddBytes(KindTCP, 1, 2)
	m.ACMEResult(ACMEObtained)
	called := false
	m.InstrumentHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), func(http.ResponseWriter) { called = true })
	if !called {
		t.Error("InstrumentHTTP on nil must still serve")
	}
}

func TestCounters(t *testing.T) {
	m := New("v1")
	m.HandshakeFailed("unauthorized")
	m.HandshakeFailed("unauthorized")
	m.SSHAuthFailed()
	m.ConnOutcome(KindTCP, OutcomeLimit)
	m.ConnOutcome(KindSSH, OutcomeRefused)
	m.AddBytes(KindTCP, 10, 20)
	m.AddBytes(KindSSH, 0, 5)
	m.ACMEResult(ACMEFailed)

	for _, tc := range []struct {
		name string
		got  float64
		want float64
	}{
		{"handshake", testutil.ToFloat64(m.hsFailures.WithLabelValues("unauthorized")), 2},
		{"ssh auth", testutil.ToFloat64(m.sshAuthFail), 1},
		{"tcp limit", testutil.ToFloat64(m.connections.WithLabelValues(KindTCP, OutcomeLimit)), 1},
		{"ssh refused", testutil.ToFloat64(m.connections.WithLabelValues(KindSSH, OutcomeRefused)), 1},
		{"tcp in", testutil.ToFloat64(m.bytes.WithLabelValues("in", KindTCP)), 10},
		{"tcp out", testutil.ToFloat64(m.bytes.WithLabelValues("out", KindTCP)), 20},
		{"ssh out", testutil.ToFloat64(m.bytes.WithLabelValues("out", KindSSH)), 5},
		{"acme failed", testutil.ToFloat64(m.acme.WithLabelValues(ACMEFailed)), 1},
		{"acme obtained", testutil.ToFloat64(m.acme.WithLabelValues(ACMEObtained)), 0},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestInstrumentHTTP(t *testing.T) {
	m := New("v1")
	reply := func(code int, body string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			if code != 0 {
				w.WriteHeader(code)
			}
			_, _ = io.WriteString(w, body)
		}
	}
	post := func(serve func(http.ResponseWriter)) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
		m.InstrumentHTTP(httptest.NewRecorder(), req, func(w http.ResponseWriter) {
			_, _ = io.Copy(io.Discard, req.Body)
			serve(w)
		})
	}
	post(reply(0, "hello"))  // implicit 200
	post(reply(404, "nope")) // 4xx
	post(reply(502, ""))     // 5xx
	post(reply(0, ""))       // writes nothing: net/http answers 200

	for class, want := range map[string]float64{"2xx": 2, "4xx": 1, "5xx": 1, "3xx": 0} {
		if got := testutil.ToFloat64(m.httpRequests.WithLabelValues(class)); got != want {
			t.Errorf("class %s = %v, want %v", class, got, want)
		}
	}
	if got := testutil.ToFloat64(m.httpIn); got != 20 {
		t.Errorf("request bytes = %v, want 20", got)
	}
	if got := testutil.ToFloat64(m.httpOut); got != 9 {
		t.Errorf("response bytes = %v, want 9", got)
	}
}

func TestStatusWriterInterfaces(t *testing.T) {
	var w http.ResponseWriter = &statusWriter{ResponseWriter: httptest.NewRecorder()}
	if _, ok := w.(http.Flusher); !ok {
		t.Error("statusWriter must implement http.Flusher")
	}
	if _, ok := w.(http.Hijacker); !ok {
		t.Error("statusWriter must implement http.Hijacker")
	}
	if _, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok {
		t.Error("statusWriter must expose Unwrap for http.ResponseController")
	}
}

func TestStateCollectorAndBuildInfo(t *testing.T) {
	m := New("1.2.3")
	m.SetStateSource(func() State {
		return State{Sessions: 2, Tunnels: map[string]int{KindHTTP: 3, KindSSH: 1}}
	})
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`porthole_build_info{version="1.2.3"} 1`,
		"porthole_sessions 2",
		`porthole_tunnels{kind="http"} 3`,
		`porthole_tunnels{kind="tcp"} 0`,
		`porthole_tunnels{kind="ssh"} 1`,
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
	rec = httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/cmdline", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("pprof cmdline status %d", rec.Code)
	}
}
