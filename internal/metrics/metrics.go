// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package metrics holds the Prometheus instrumentation of portholed and the HTTP handler that serves it together
// with the Go profiler. It uses its own registry (never the global default), so embedding the server in another
// program or in tests cannot clash with other users of client_golang.
//
// Every hook is safe to call on a nil *Metrics and does nothing then, so the server code calls them
// unconditionally. Label values are drawn from small fixed sets: nothing here is labelled by tunnel, client,
// host or address (cardinality).
package metrics

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "porthole"

// Tunnel kinds, as in the protocol (internal/proto). Declared here so that the package stays a leaf.
const (
	KindHTTP = "http"
	KindTCP  = "tcp"
	KindSSH  = "ssh"
)

// Outcomes of TCP and SSH connections, for ConnOutcome.
const (
	OutcomeAccepted    = "accepted"     // a stream to the tunnel client was opened and bytes were piped
	OutcomeLimit       = "limit"        // refused: the tunnel is at its connection limit
	OutcomeStreamError = "stream_error" // refused: the tunnel client did not open a stream
	OutcomeRefused     = "refused"      // refused: unknown target or not permitted (ssh gateway)
)

// Results of certificate issuance, for ACMEResult.
const (
	ACMEObtained = "obtained"
	ACMEFailed   = "failed"
)

// State is a point-in-time view of the server registry, read at every scrape.
type State struct {
	Sessions int            // live sessions
	Tunnels  map[string]int // live tunnels by kind
}

// Metrics is the set of porthole metrics.
type Metrics struct {
	reg *prometheus.Registry

	state atomic.Pointer[func() State]

	httpRequests *prometheus.CounterVec
	httpDuration prometheus.Histogram
	bytes        *prometheus.CounterVec
	httpIn       prometheus.Counter
	httpOut      prometheus.Counter
	connections  *prometheus.CounterVec
	sshAuthFail  prometheus.Counter
	hsFailures   *prometheus.CounterVec
	acme         *prometheus.CounterVec
}

// New returns a Metrics with its own registry, the Go runtime and process collectors, and porthole_build_info
// labelled with version.
func New(version string) *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry()}
	m.httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "http_requests_total",
		Help: "HTTP requests to tunnel hosts, by response status class.",
	}, []string{"status_class"})
	m.httpDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Name: "http_request_duration_seconds",
		Help:    "Time from receiving a request to tunnel hosts until the response was fully written.",
		Buckets: []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
	})
	m.bytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "bytes_total",
		Help: "Bytes relayed. direction=in is from visitors towards tunnel clients, direction=out the other way.",
	}, []string{"direction", "kind"})
	m.httpIn = m.bytes.WithLabelValues("in", KindHTTP)
	m.httpOut = m.bytes.WithLabelValues("out", KindHTTP)
	m.connections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "tcp_connections_total",
		Help: "Connections to TCP tunnels and SSH gateway channels, by tunnel kind and outcome.",
	}, []string{"kind", "outcome"})
	m.sshAuthFail = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Name: "ssh_gateway_auth_failures_total",
		Help: "Failed token logins at the SSH gateway.",
	})
	m.hsFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "handshake_failures_total",
		Help: "Control handshakes that ended in an error sent to the client, by protocol error code.",
	}, []string{"reason"})
	m.acme = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "acme_certificates_total",
		Help: "Certificate issuance and renewal attempts, by result.",
	}, []string{"result"})
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Constant 1, labelled with the portholed version.",
	}, []string{"version"})
	build.WithLabelValues(version).Set(1)

	// Series that would otherwise appear only after the first event, so that rate() and absent() work.
	for _, kind := range []string{KindTCP, KindSSH} {
		for _, o := range []string{OutcomeAccepted, OutcomeLimit, OutcomeStreamError} {
			m.connections.WithLabelValues(kind, o)
		}
	}
	m.connections.WithLabelValues(KindSSH, OutcomeRefused)
	m.bytes.WithLabelValues("in", KindTCP)
	m.bytes.WithLabelValues("out", KindTCP)
	m.bytes.WithLabelValues("in", KindSSH)
	m.bytes.WithLabelValues("out", KindSSH)
	m.acme.WithLabelValues(ACMEObtained)
	m.acme.WithLabelValues(ACMEFailed)

	m.reg.MustRegister(
		m.httpRequests, m.httpDuration, m.bytes, m.connections, m.sshAuthFail, m.hsFailures, m.acme, build,
		&stateCollector{m: m},
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Registry returns the registry, for tests and for embedding.
func (m *Metrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.reg
}

// SetStateSource installs the function that reports live sessions and tunnels. It is called at every scrape and
// must be quick and safe for concurrent use. Gauges are computed from the registry at scrape time instead of
// being incremented and decremented at every registration path, so they cannot drift.
func (m *Metrics) SetStateSource(fn func() State) {
	if m == nil {
		return
	}
	m.state.Store(&fn)
}

// stateCollector exposes porthole_sessions and porthole_tunnels from the state source.
type stateCollector struct{ m *Metrics }

var (
	sessionsDesc = prometheus.NewDesc(namespace+"_sessions", "Connected client sessions.", nil, nil)
	tunnelsDesc  = prometheus.NewDesc(namespace+"_tunnels", "Registered tunnels, by kind.", []string{"kind"}, nil)
)

func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- sessionsDesc
	ch <- tunnelsDesc
}

func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	var st State
	if fn := c.m.state.Load(); fn != nil {
		st = (*fn)()
	}
	ch <- prometheus.MustNewConstMetric(sessionsDesc, prometheus.GaugeValue, float64(st.Sessions))
	for _, kind := range []string{KindHTTP, KindTCP, KindSSH} {
		ch <- prometheus.MustNewConstMetric(tunnelsDesc, prometheus.GaugeValue, float64(st.Tunnels[kind]), kind)
	}
}

// Handler returns the handler of the metrics listener: /metrics and the pprof endpoints under /debug/pprof/.
// It is registered on its own mux, not on http.DefaultServeMux.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		Registry:            m.reg,
		EnableOpenMetrics:   false,
		MaxRequestsInFlight: 4,
	}))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// HandshakeFailed counts a control handshake that was answered with an error; reason is the protocol error code.
func (m *Metrics) HandshakeFailed(reason string) {
	if m != nil {
		m.hsFailures.WithLabelValues(reason).Inc()
	}
}

// SSHAuthFailed counts a failed token login at the SSH gateway.
func (m *Metrics) SSHAuthFailed() {
	if m != nil {
		m.sshAuthFail.Inc()
	}
}

// ConnOutcome counts a connection to a TCP tunnel or an SSH gateway channel (kind KindTCP or KindSSH).
func (m *Metrics) ConnOutcome(kind, outcome string) {
	if m != nil {
		m.connections.WithLabelValues(kind, outcome).Inc()
	}
}

// AddBytes adds the bytes relayed over one finished TCP or SSH connection: in from the visitor towards the tunnel
// client, out the other way.
func (m *Metrics) AddBytes(kind string, in, out int64) {
	if m == nil {
		return
	}
	if in > 0 {
		m.bytes.WithLabelValues("in", kind).Add(float64(in))
	}
	if out > 0 {
		m.bytes.WithLabelValues("out", kind).Add(float64(out))
	}
}

// ACMEResult counts a certificate issuance or renewal attempt (ACMEObtained or ACMEFailed).
func (m *Metrics) ACMEResult(result string) {
	if m != nil {
		m.acme.WithLabelValues(result).Inc()
	}
}

// InstrumentHTTP runs serve, which answers a request to a tunnel host, and records the response status class, the
// duration and the body bytes in both directions. Upgraded (hijacked) connections count as 101 and only their
// handshake bytes are seen: what flows afterwards bypasses the ResponseWriter.
func (m *Metrics) InstrumentHTTP(w http.ResponseWriter, r *http.Request, serve func(http.ResponseWriter)) {
	if m == nil {
		serve(w)
		return
	}
	start := time.Now()
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &countingBody{ReadCloser: r.Body, c: m.httpIn}
	}
	rw := &statusWriter{ResponseWriter: w, out: m.httpOut}
	defer func() {
		m.httpRequests.WithLabelValues(statusClass(rw.status)).Inc()
		m.httpDuration.Observe(time.Since(start).Seconds())
	}()
	serve(rw)
}

func statusClass(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	}
	return "other"
}

type countingBody struct {
	io.ReadCloser
	c prometheus.Counter
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.c.Add(float64(n))
	}
	return n, err
}

// statusWriter records the status code and counts written bytes. It keeps http.Flusher and http.Hijacker (needed
// for streaming and WebSocket upgrades) and exposes the wrapped writer through Unwrap for http.ResponseController.
type statusWriter struct {
	http.ResponseWriter
	out    prometheus.Counter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	// Informational responses (1xx) other than 101 do not end the response; the final status follows.
	if w.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.out.Add(float64(n))
	}
	return n, err
}

func (w *statusWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil && w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ReadFrom keeps io.Copy from bypassing the byte counter through the wrapped writer's own ReadFrom.
func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(writerOnly{w}, r)
}

type writerOnly struct{ io.Writer }
