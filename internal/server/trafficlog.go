// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/traffic"
)

// Traffic returns the journal of proxied requests and tunnel connections (ADR 0005). The result is never nil;
// a journal sized 0 in the configuration records nothing.
func (s *Server) Traffic() *traffic.Log { return s.traffic }

// recordConn stores one connection entry; start is when the connection was accepted.
func (s *Server) recordConn(c traffic.Conn, start time.Time) {
	conns := s.traffic.Conns()
	if !conns.Enabled() {
		return
	}
	c.Start = start
	c.Duration = time.Since(start)
	conns.Add(c)
}

// respRecorder wraps the ResponseWriter of a tunnelled request to learn the status and the number of body bytes
// the visitor receives. For a hijacked connection (WebSocket upgrade) it counts the bytes of the raw connection.
type respRecorder struct {
	http.ResponseWriter
	status   int
	bytes    atomic.Int64 // response body bytes, or bytes written to a hijacked connection
	hijackIn atomic.Int64 // bytes the visitor sent over a hijacked connection
	hijacked bool
	upgraded time.Time // set at Hijack: the latency of an upgrade ends there

	// Inspection: the response headers when the status was decided, and the first bytes of the body.
	body    *capture
	headers http.Header
}

func (w *respRecorder) WriteHeader(code int) {
	if w.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
		w.snapshot()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *respRecorder) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
		w.snapshot()
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes.Add(int64(n))
	w.body.write(p[:n])
	return n, err
}

// snapshot keeps a copy of the response headers as they are sent (inspected tunnels only).
func (w *respRecorder) snapshot() {
	if w.body != nil {
		w.headers = w.Header().Clone()
	}
}

func (w *respRecorder) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *respRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack hands out the connection wrapped in a byte counter and records the upgrade as status 101.
func (w *respRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.hijacked = true
	w.status = http.StatusSwitchingProtocols
	w.upgraded = time.Now()
	return &countingConn{Conn: conn, rec: w}, rw, nil
}

// countingConn counts the bytes of a hijacked connection: reads are visitor to tunnel, writes the other way.
type countingConn struct {
	net.Conn
	rec *respRecorder
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rec.hijackIn.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.rec.bytes.Add(int64(n))
	return n, err
}

// countingBody counts the bytes the visitor sends as the request body.
type countingBody struct {
	io.ReadCloser
	n    atomic.Int64
	copy *capture // the first bytes of the body, inspected tunnels only
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	b.copy.write(p[:n])
	return n, err
}

// capture keeps the first traffic.MaxBodyBytes of a stream and counts all of it. A nil *capture ignores writes.
type capture struct {
	mu   sync.Mutex
	buf  []byte
	size int64
}

func (c *capture) write(p []byte) {
	if c == nil || len(p) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.size += int64(len(p))
	if room := traffic.MaxBodyBytes - len(c.buf); room > 0 {
		c.buf = append(c.buf, p[:min(room, len(p))]...)
	}
}

func (c *capture) body() traffic.Body {
	if c == nil {
		return traffic.Body{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return traffic.Body{Data: c.buf, Size: c.size, Truncated: c.size > int64(len(c.buf))}
}

// newTrafficLog builds the journals as configured.
func newTrafficLog(c config.Traffic) *traffic.Log {
	l := traffic.NewLog(c.MaxRequests, c.MaxConns)
	l.Requests().SetMaxDetailBytes(c.MaxDetailBytes)
	return l
}

// serveRecorded runs the tunnel's reverse proxy and records the request after the response (or after the end of
// an upgraded connection). The record is written even when the proxy aborts the handler with a panic.
func (s *Server) serveRecorded(t *tunnel, w http.ResponseWriter, r *http.Request) {
	s.serveLogged(t, w, r, 0, nil)
}

// serveLogged is serveRecorded for a request that may replay an earlier one (replayOf is its id, else 0). It
// stores the id of the journal entry in *idOut (when not nil), 0 if none was written.
func (s *Server) serveLogged(t *tunnel, w http.ResponseWriter, r *http.Request, replayOf uint64, idOut *uint64) {
	reqs := s.traffic.Requests()
	if !reqs.Enabled() {
		t.handler.ServeHTTP(w, r)
		return
	}
	arrived := s.now()
	begin := time.Now()
	rec := &respRecorder{ResponseWriter: w}
	body := &countingBody{}
	// Upgrades (WebSocket) are never inspected: after the switch the bytes are not HTTP.
	inspect := t.inspect && r.Header.Get("Upgrade") == ""
	var detail *traffic.Detail
	if inspect {
		rec.body, body.copy = &capture{}, &capture{}
		detail = &traffic.Detail{RequestHeaders: r.Header.Clone(), Target: r.URL.RequestURI()}
	}
	if r.Body != nil && r.Body != http.NoBody {
		body.ReadCloser = r.Body
		r.Body = body
	}
	defer func() {
		status := rec.status
		if status == 0 {
			status = http.StatusOK // net/http's implicit reply
		}
		latency := time.Since(begin)
		if rec.hijacked {
			latency = rec.upgraded.Sub(begin)
		}
		e := s.requestEntry(r, arrived, status, latency, body.n.Load()+rec.hijackIn.Load(), rec.bytes.Load(), t)
		e.ReplayOf = replayOf
		if detail != nil && !rec.hijacked {
			detail.RequestBody, detail.ResponseBody, detail.ResponseHeaders = body.copy.body(), rec.body.body(), rec.headers
			e.Detail = detail
		}
		if id := reqs.Add(e); idOut != nil {
			*idOut = id
		}
	}()
	t.handler.ServeHTTP(rec, r)
}

// requestEntry builds the journal entry for r; t is nil when no tunnel handled it (the client is offline).
func (s *Server) requestEntry(r *http.Request, at time.Time, status int, latency time.Duration, in, out int64, t *tunnel) traffic.Request {
	e := traffic.Request{
		Time:      at,
		VisitorIP: ipOf(visitorAddr(r, s.cfg.TrustProxyHeaders)),
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Status:    status,
		Latency:   latency,
		BytesIn:   in,
		BytesOut:  out,
		UserAgent: r.UserAgent(),
		Referer:   r.Referer(),
	}
	if t != nil {
		e.TunnelID, e.Tunnel, e.Label, e.Client = t.id, t.name, t.label, t.sess.name
	}
	return e
}
