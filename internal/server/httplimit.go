// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// stallKey carries the *atomic.Bool that idleBody sets when it cuts a stalled request body off.
type stallKey struct{}

// idleBody aborts a request body that stalls: every Read must make progress within idle. The deadline is set on
// the connection only for the duration of one Read and cleared afterwards, so it neither limits the total upload
// time (large, slow but steady uploads work) nor leaks into the response phase (streaming responses, the server's
// background read that notices a vanished visitor).
type idleBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	idle    time.Duration
	stalled *atomic.Bool
}

func (b *idleBody) Read(p []byte) (int, error) {
	_ = b.rc.SetReadDeadline(time.Now().Add(b.idle)) // ErrNotSupported (tests, wrapped writers): no limit
	n, err := b.ReadCloser.Read(p)
	_ = b.rc.SetReadDeadline(time.Time{})
	if errors.Is(err, os.ErrDeadlineExceeded) {
		b.stalled.Store(true)
	}
	return n, err
}

// Close lets net/http drain what is left of the body, which reads from the connection: bound that read too, and give
// it no time at all once the body has already stalled.
func (b *idleBody) Close() error {
	d := b.idle
	if b.stalled.Load() {
		d = 0
	}
	_ = b.rc.SetReadDeadline(time.Now().Add(d))
	err := b.ReadCloser.Close()
	_ = b.rc.SetReadDeadline(time.Time{})
	return err
}

// limitBody installs the stall timeout on r's body and returns the request to use from now on. WebSocket upgrades
// and requests without a body are left alone.
func (s *Server) limitBody(w http.ResponseWriter, r *http.Request) *http.Request {
	if s.bodyIdle <= 0 || r.Body == nil || r.Body == http.NoBody || r.Header.Get("Upgrade") != "" {
		return r
	}
	stalled := new(atomic.Bool)
	r = r.WithContext(context.WithValue(r.Context(), stallKey{}, stalled))
	r.Body = &idleBody{ReadCloser: r.Body, rc: http.NewResponseController(w), idle: s.bodyIdle, stalled: stalled}
	return r
}

// bodyStalled reports whether the request's body was cut off by limitBody. The error handler then closes the
// connection with the reply: without that, net/http would first try to drain the rest of the body that never comes
// before it sends the response.
func bodyStalled(r *http.Request) bool {
	st, _ := r.Context().Value(stallKey{}).(*atomic.Bool)
	return st != nil && st.Load()
}

// acquireHTTP takes one request slot of t; it returns the release function, or nil when the tunnel is at its limit.
func (t *tunnel) acquireHTTP() func() {
	if t.httpSem == nil {
		return func() {}
	}
	select {
	case t.httpSem <- struct{}{}:
		return func() { <-t.httpSem }
	default:
		return nil
	}
}
