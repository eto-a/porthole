// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/eto-a/porthole/internal/traffic"
)

// Errors of ReplayRequest.
var (
	// ErrRequestNotFound means the request is not (or no longer) in the journal.
	ErrRequestNotFound = errors.New("server: request not found in the traffic log")
	// ErrReplayRefused means the request exists but cannot be replayed; the wrapped text says why.
	ErrReplayRefused = errors.New("server: request cannot be replayed")
)

// replayTimeout bounds one replayed request, which runs outside any visitor connection.
const replayTimeout = 30 * time.Second

// replayDropped are request headers that are not sent again: the proxy sets its own forwarding headers, the
// body length is recomputed and a replay is not an upgrade.
var replayDropped = []string{
	"Content-Length", "Connection", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
	"X-Forwarded-Proto", "X-Real-Ip",
}

// ReplayRequest sends the request with the given journal id again through the handler of its tunnel (not over
// the network) and returns the new journal entry, whose ReplayOf is id. The request must have been inspected
// with its detail still kept and its body must not be truncated. Headers that were stored as REDACTED
// (Authorization, Cookie, ...) are not sent, so a replay of an authenticated request reaches the service
// without credentials.
func (s *Server) ReplayRequest(ctx context.Context, id uint64) (traffic.Request, error) {
	reqs := s.traffic.Requests()
	orig, ok := reqs.Get(id)
	if !ok {
		return traffic.Request{}, ErrRequestNotFound
	}
	d := orig.Detail
	switch {
	case d == nil:
		return traffic.Request{}, fmt.Errorf("%w: the request was not inspected, or its detail was dropped to stay within traffic.max_detail_bytes", ErrReplayRefused)
	case d.RequestBody.Truncated:
		return traffic.Request{}, fmt.Errorf("%w: the request body was truncated to %d bytes", ErrReplayRefused, traffic.MaxBodyBytes)
	case d.Target == "":
		return traffic.Request{}, fmt.Errorf("%w: the request target was not recorded", ErrReplayRefused)
	}

	t := s.replayTarget(&orig)
	switch {
	case t == nil:
		return traffic.Request{}, fmt.Errorf("%w: the tunnel is offline", ErrReplayRefused)
	case !t.inspect:
		return traffic.Request{}, fmt.Errorf("%w: the tunnel is no longer inspected", ErrReplayRefused)
	}

	ctx, cancel := context.WithTimeout(ctx, replayTimeout)
	defer cancel()
	body := io.NopCloser(bytes.NewReader(d.RequestBody.Data))
	r, err := http.NewRequestWithContext(ctx, orig.Method, "http://"+orig.Host+d.Target, body)
	if err != nil {
		return traffic.Request{}, fmt.Errorf("%w: %w", ErrReplayRefused, err)
	}
	r.RequestURI = d.Target
	r.RemoteAddr = "127.0.0.1:0"
	r.ContentLength = int64(len(d.RequestBody.Data))
	if r.ContentLength == 0 {
		r.Body = http.NoBody
	}
	for k, vs := range d.RequestHeaders {
		if traffic.IsRedactedHeader(k) || droppedOnReplay(k) {
			continue
		}
		r.Header[k] = append([]string(nil), vs...)
	}
	// A replay takes a request slot like a visitor does: it must not push the tunnel's client beyond the limit.
	release := t.acquireHTTP()
	if release == nil {
		return traffic.Request{}, fmt.Errorf("%w: the tunnel is busy (at its limit of %d simultaneous requests); try again", ErrReplayRefused, cap(t.httpSem))
	}
	defer release()
	newID := s.replayServe(t, r, orig.ID)
	if newID == 0 {
		return traffic.Request{}, errors.New("server: the replayed request was not recorded")
	}
	out, ok := reqs.Get(newID)
	if !ok {
		return traffic.Request{}, fmt.Errorf("%w: the replayed request left the traffic log before it could be read", ErrReplayRefused)
	}
	return out, nil
}

// replayTarget finds the live tunnel a recorded request goes back to: the tunnel it was recorded on, or, if its client
// reconnected meanwhile (new tunnel id), the tunnel with the same label that belongs to the same client and has the
// same name. A label alone is not enough: labels are name + "-" + client, so another client can hold the same one,
// and the stored request (body, credential headers kept by the inspector) must not be sent to it.
func (s *Server) replayTarget(orig *traffic.Request) *tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()
	if orig.TunnelID != "" {
		for _, c := range s.sessions {
			if t := c.tunnels[orig.TunnelID]; t != nil {
				return t
			}
		}
	}
	t := s.labels[orig.Label]
	if t == nil || t.sess == nil || t.sess.name != orig.Client || (orig.Tunnel != "" && t.name != orig.Tunnel) {
		return nil
	}
	return t
}

func droppedOnReplay(name string) bool {
	for _, d := range replayDropped {
		if strings.EqualFold(name, d) {
			return true
		}
	}
	return false
}

// replayServe runs r through the tunnel exactly like a visitor request, discarding the response body.
func (s *Server) replayServe(t *tunnel, r *http.Request, of uint64) (id uint64) {
	defer func() {
		// ReverseProxy aborts with http.ErrAbortHandler when the backend fails mid-body; the entry is still written.
		if v := recover(); v != nil && v != http.ErrAbortHandler { //nolint:errorlint // recover returns the sentinel itself
			panic(v)
		}
	}()
	w := &discardWriter{h: make(http.Header)}
	s.serveLogged(t, w, s.limitBody(w, r), of, &id)
	return id
}

// discardWriter is a ResponseWriter that drops the body.
type discardWriter struct {
	h http.Header
}

func (w *discardWriter) Header() http.Header         { return w.h }
func (w *discardWriter) WriteHeader(int)             {}
func (w *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
