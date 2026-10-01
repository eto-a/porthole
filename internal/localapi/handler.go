// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/eto-a/porthole/internal/proto"
)

const (
	bodyReadTimeout    = 10 * time.Second
	streamWriteTimeout = 10 * time.Second
	removeTimeout      = 5 * time.Second
)

// handler serves the /v1 API over a Backend.
type handler struct {
	b   Backend
	log *slog.Logger
	mux *http.ServeMux
}

// NewHandler returns the HTTP handler of the local API. It rejects requests whose Host is not "porthole" and any
// request carrying an Origin or Referer header (a browser can never be the caller), caps request bodies at
// [MaxBodyBytes] and logs the peer credentials (see [ConnContext]) of every mutating call. A nil log discards logs.
func NewHandler(b Backend, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &handler{b: b, log: log, mux: http.NewServeMux()}

	h.mux.HandleFunc("GET /v1/status", h.status)
	h.mux.HandleFunc("GET /v1/tunnels", h.listTunnels)
	h.mux.HandleFunc("POST /v1/tunnels", h.addTunnel)
	h.mux.HandleFunc("DELETE /v1/tunnels/{name}", h.removeTunnel)
	h.mux.HandleFunc("POST /v1/reload", h.reload)
	h.mux.HandleFunc("GET /v1/events", h.events)

	// Method-less fallbacks give JSON 405 (the mux would answer in plain text) and a JSON 404 for the rest.
	h.mux.HandleFunc("/v1/status", methodNotAllowed(http.MethodGet))
	h.mux.HandleFunc("/v1/tunnels", methodNotAllowed(http.MethodGet, http.MethodPost))
	h.mux.HandleFunc("/v1/tunnels/{name}", methodNotAllowed(http.MethodDelete))
	h.mux.HandleFunc("/v1/reload", methodNotAllowed(http.MethodPost))
	h.mux.HandleFunc("/v1/events", methodNotAllowed(http.MethodGet))
	h.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, NewError(CodeNotFound, "no such endpoint"))
	})
	return h
}

func methodNotAllowed(allow ...string) http.HandlerFunc {
	hdr := ""
	for i, m := range allow {
		if i > 0 {
			hdr += ", "
		}
		hdr += m
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", hdr)
		writeError(w, http.StatusMethodNotAllowed, NewError(CodeInvalidRequest, "method %s not allowed", r.Method))
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")

	switch {
	case r.Host != Host:
		h.reject(w, r, "bad host")
		return
	case len(r.Header.Values("Origin")) > 0 || len(r.Header.Values("Referer")) > 0:
		h.reject(w, r, "origin or referer present")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.log.InfoContext(r.Context(), "local api mutating request",
			append([]any{"method", r.Method, "path", r.URL.Path}, peerAttrs(r.Context())...)...)
	}
	h.mux.ServeHTTP(w, r)
}

func (h *handler) reject(w http.ResponseWriter, r *http.Request, reason string) {
	h.log.WarnContext(r.Context(), "local api request rejected", "reason", reason, "method", r.Method)
	writeError(w, http.StatusForbidden, NewError(CodeForbidden, "request rejected: %s", reason))
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	st := h.b.Status(r.Context())
	if st.Tunnels == nil {
		st.Tunnels = []Tunnel{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *handler) listTunnels(w http.ResponseWriter, r *http.Request) {
	ts := h.b.Tunnels(r.Context())
	if ts == nil {
		ts = []Tunnel{}
	}
	writeJSON(w, http.StatusOK, ts)
}

func (h *handler) addTunnel(w http.ResponseWriter, r *http.Request) {
	var req AddTunnelRequest
	if status, e := decodeBody(w, r, &req); e != nil {
		writeError(w, status, e)
		return
	}
	if req.Lifetime == "" {
		req.Lifetime = LifetimeAttached
	}
	if e := validateAdd(req); e != nil {
		writeError(w, http.StatusBadRequest, e)
		return
	}
	if req.Lifetime == LifetimeAttached {
		h.attach(w, r, req)
		return
	}
	t, err := h.b.AddTunnel(r.Context(), req)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func validateAdd(req AddTunnelRequest) *Error {
	switch req.Type {
	case TypeHTTP, TypeTCP, TypeSSH:
	default:
		return NewError(CodeInvalidRequest, "type must be http, tcp or ssh")
	}
	switch req.Lifetime {
	case LifetimeAttached, LifetimeRuntime:
	default:
		return NewError(CodeInvalidRequest, "lifetime must be attached or runtime")
	}
	return nil
}

// attach serves an attached tunnel: it streams events about the tunnel until the caller goes away, then removes it.
func (h *handler) attach(w http.ResponseWriter, r *http.Request, req AddTunnelRequest) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Subscribe before adding so that no event of the new tunnel can be missed.
	events := h.b.Subscribe(ctx)
	t, err := h.b.AddTunnel(ctx, req)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	defer h.release(r.Context(), t.Name)

	s := newStream(w)
	defer s.finish()
	if s.send(Event{Type: EventAttached, Name: t.Name, PublicURL: t.PublicURL, Time: time.Now().UTC(), Tunnel: &t}) != nil {
		return
	}
	s.pump(ctx, events, func(ev Event) bool {
		return ev.Type == EventConnected || ev.Type == EventDisconnected || ev.Name == t.Name
	})
}

// release removes an attached tunnel after its request ended. The request context is already cancelled then.
func (h *handler) release(ctx context.Context, name string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), removeTimeout)
	defer cancel()
	if err := h.b.RemoveTunnel(rctx, name); err != nil {
		var e *Error
		if errors.As(err, &e) && e.Code == CodeNotFound {
			return
		}
		h.log.WarnContext(ctx, "removing attached tunnel failed", "tunnel", name, "err", err)
	}
}

func (h *handler) removeTunnel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, NewError(CodeInvalidRequest, "tunnel name is required"))
		return
	}
	if err := h.b.RemoveTunnel(r.Context(), name); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) reload(w http.ResponseWriter, r *http.Request) {
	res, err := h.b.Reload(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if res.Added == nil {
		res.Added = []string{}
	}
	if res.Removed == nil {
		res.Removed = []string{}
	}
	if res.Changed == nil {
		res.Changed = []string{}
	}
	if res.Unchanged == nil {
		res.Unchanged = []string{}
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handler) events(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	events := h.b.Subscribe(ctx)
	s := newStream(w)
	defer s.finish()
	s.pump(ctx, events, nil)
}

// fail writes a backend error. Errors that are not *Error are logged and reported as internal without details.
func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var e *Error
	if !errors.As(err, &e) {
		h.log.ErrorContext(r.Context(), "local api backend error", "method", r.Method, "path", r.URL.Path, "err", err)
		e = NewError(CodeInternal, "internal error")
	}
	writeError(w, statusFor(e.Code), e)
}

// statusFor maps an error code to an HTTP status.
func statusFor(code string) int {
	switch code {
	case CodeInvalidRequest:
		return http.StatusBadRequest
	case proto.CodeUnauthorized, proto.CodeTokenExpired, proto.CodeTokenRevoked:
		return http.StatusUnauthorized
	case CodeForbidden:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeNameTaken, CodeConflict, proto.CodePortUnavailable, proto.CodeSessionReplaced:
		return http.StatusConflict
	case proto.CodeLimitExceeded:
		return http.StatusTooManyRequests
	case proto.CodeShuttingDown:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

type errorBody struct {
	Error *Error `json:"error"`
}

func writeError(w http.ResponseWriter, status int, e *Error) {
	writeJSON(w, status, errorBody{Error: e})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"code":"internal","message":"encoding response failed"}}`+"\n")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// decodeBody reads one JSON value (at most MaxBodyBytes) into dst, rejecting unknown fields and trailing data.
// On failure it returns the HTTP status to use.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) (int, *Error) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyReadTimeout))
	defer func() { _ = rc.SetReadDeadline(time.Time{}) }()

	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return http.StatusRequestEntityTooLarge, NewError(CodeInvalidRequest, "request body larger than %d bytes", MaxBodyBytes)
		}
		return http.StatusBadRequest, NewError(CodeInvalidRequest, "reading request body failed")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return http.StatusBadRequest, NewError(CodeInvalidRequest, "invalid JSON body: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return http.StatusBadRequest, NewError(CodeInvalidRequest, "invalid JSON body: unexpected data after the value")
	}
	return 0, nil
}

// stream writes NDJSON, flushing every line.
type stream struct {
	rc  *http.ResponseController
	enc *json.Encoder
}

func newStream(w http.ResponseWriter) *stream {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	s := &stream{rc: http.NewResponseController(w), enc: json.NewEncoder(w)}
	_ = s.rc.Flush()
	return s
}

func (s *stream) send(v any) error {
	_ = s.rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	if err := s.enc.Encode(v); err != nil {
		return err
	}
	return s.rc.Flush()
}

// finish clears the write deadline so that a kept-alive connection is not left with a stale one.
func (s *stream) finish() { _ = s.rc.SetWriteDeadline(time.Time{}) }

// pump forwards events (all, or those for which keep returns true) until ctx is done, the channel is closed or a
// write fails.
func (s *stream) pump(ctx context.Context, events <-chan Event, keep func(Event) bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if keep != nil && !keep(ev) {
				continue
			}
			if s.send(ev) != nil {
				return
			}
		}
	}
}
