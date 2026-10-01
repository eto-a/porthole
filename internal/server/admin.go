// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/traffic"
)

const adminReadHeaderTimeout = 10 * time.Second

// newAdminAPI builds the admin API over this server's registry and store.
func (s *Server) newAdminAPI() (*adminapi.API, error) {
	return adminapi.New(adminapi.Options{
		Backend:      adminBackend{s},
		Store:        s.store,
		Authenticate: s.adminAuthenticate,
		ClientIP:     func(r *http.Request) string { return ipOf(visitorAddr(r, s.cfg.TrustProxyHeaders)) },
		Now:          s.now,
		Logger:       s.log,
		ServerURL:    s.cfg.PublicURL(),
	})
}

// adminAuthenticate checks a bearer token for the admin API with the same rules and the same per-IP failure
// limiter as the control handshake.
func (s *Server) adminAuthenticate(ctx context.Context, ip, raw string) (*store.Token, error) {
	if wait, blocked := s.limiter.blocked(ip, s.now()); blocked {
		s.log.Warn("admin request refused: too many failed attempts", "ip", ip)
		return nil, &adminapi.RateLimitedError{RetryAfter: wait}
	}
	tok, perr, fromClient := s.authenticate(ctx, raw)
	if perr == nil {
		return tok, nil
	}
	if fromClient {
		s.limiter.fail(ip, s.now())
		s.log.Warn("admin authentication failed", "ip", ip, "code", perr.Code)
	}
	if perr.Code == proto.CodeInternal {
		return nil, errors.New("server: " + perr.Message)
	}
	return nil, adminapi.ErrUnauthorized
}

// serveAdmin handles Prefix/... on the control host: bearer-token access to the admin API.
func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request) {
	if s.ctx.Err() != nil {
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
		return
	}
	s.adminBearer.ServeHTTP(w, r)
}

func isAdminPath(p string) bool { return strings.HasPrefix(p, adminapi.Prefix+"/") }

// startAdminSocket opens the unix socket configured by admin_socket, unless it is turned off or unsupported.
func (s *Server) startAdminSocket(ctx context.Context) error {
	path := s.cfg.AdminSocketPath()
	if path == "" {
		return nil
	}
	if !adminapi.SocketSupported {
		s.log.Info("admin socket is not supported on this platform; the bearer endpoint is still served")
		return nil
	}
	ln, err := adminapi.ListenUnix(ctx, path)
	if err != nil {
		if s.cfg.AdminSocket == "" {
			// The default socket is a convenience; a path the platform cannot bind (macOS caps unix socket paths
			// at 104 bytes) must not keep the server down. An explicitly configured socket is still required.
			s.log.Warn("admin socket unavailable; the bearer endpoint is still served", "path", path, "err", err)
			return nil
		}
		return fmt.Errorf("server: %w", err)
	}
	return s.StartAdminSocket(ln)
}

// StartAdminSocket serves the admin API on ln in the background until the server closes. It takes ownership of
// ln, which must be reachable only by trusted local users: every caller on it is a full administrator.
func (s *Server) StartAdminSocket(ln net.Listener) error {
	hs := &http.Server{
		Handler:           s.adminSocket,
		ReadHeaderTimeout: adminReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	if !s.start(func() {
		stop := context.AfterFunc(s.ctx, func() { _ = hs.Close() })
		defer stop()
		if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("admin socket stopped", "err", err)
		}
	}) {
		_ = ln.Close()
		return errors.New("server: closed")
	}
	s.log.Info("admin socket listening", "addr", ln.Addr().String())
	return nil
}

// adminBackend implements adminapi.Backend over the registry. It takes Server.mu like the rest of the registry.
type adminBackend struct{ s *Server }

var _ adminapi.Backend = adminBackend{}

func (b adminBackend) Status(context.Context) (adminapi.Status, error) {
	s := b.s
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := adminapi.Status{
		Version:       s.version,
		StartedAt:     s.started,
		UptimeSeconds: max(0, int64(now.Sub(s.started)/time.Second)),
		Clients:       len(s.sessions),
	}
	for _, c := range s.sessions {
		st.Tunnels += len(c.tunnels)
	}
	return st, nil
}

func (b adminBackend) Clients(context.Context) ([]adminapi.Client, error) {
	s := b.s
	s.mu.Lock()
	out := make([]adminapi.Client, 0, len(s.sessions))
	for _, c := range s.sessions {
		out = append(out, adminapi.Client{
			Name: c.name, SessionID: c.id, TokenID: c.tokenID, Remote: c.remote, ConnectedAt: c.since,
			ClientVersion: c.clientVersion, OS: c.os, Tunnels: len(c.tunnels),
		})
	}
	s.mu.Unlock()
	slices.SortFunc(out, func(a, b adminapi.Client) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Disconnect drops the client's connection without a farewell, so the client sees a lost connection and
// reconnects by itself. To keep a client out, revoke its token.
func (b adminBackend) Disconnect(_ context.Context, name string) error {
	s := b.s
	s.mu.Lock()
	c := s.sessions[name]
	s.mu.Unlock()
	if c == nil {
		return adminapi.ErrNotFound
	}
	c.log.Info("session disconnected by an administrator")
	c.kill("disconnected by an administrator", nil)
	return nil
}

func (b adminBackend) Tunnels(context.Context) ([]adminapi.Tunnel, error) {
	s := b.s
	s.mu.Lock()
	var out []adminapi.Tunnel
	for _, c := range s.sessions {
		for _, t := range c.tunnels {
			at := adminapi.Tunnel{
				ID: t.id, Client: c.name, Name: t.name, Kind: t.kind, URL: s.publicURL(t), Private: t.private, Inspect: t.inspect,
			}
			if t.kind == proto.KindTCP {
				at.Port = t.port
			}
			out = append(out, at)
		}
	}
	s.mu.Unlock()
	slices.SortFunc(out, func(a, b adminapi.Tunnel) int {
		return strings.Compare(a.Client+"/"+a.Name+"/"+a.ID, b.Client+"/"+b.Name+"/"+b.ID)
	})
	return out, nil
}

// CloseTunnel removes the tunnel from the registry and tells its client with tunnel_closed.
func (b adminBackend) CloseTunnel(_ context.Context, id string) error {
	s := b.s
	var t *tunnel
	s.mu.Lock()
	for _, c := range s.sessions {
		if t = c.tunnels[id]; t != nil {
			s.removeLocked(t, false)
			break
		}
	}
	s.mu.Unlock()
	if t == nil {
		return adminapi.ErrNotFound
	}
	s.releaseTransport(t)
	c := t.sess
	c.log.Info("tunnel closed by an administrator", "tunnel", t.id, "name", t.name)
	if err := c.send(&proto.TunnelClosed{TunnelID: t.id, Reason: "closed by an administrator"}); err != nil {
		c.kill("control write failed: "+err.Error(), nil)
	}
	return nil
}

func (b adminBackend) Requests(_ context.Context, f traffic.RequestFilter) ([]traffic.Request, error) {
	return b.s.traffic.Requests().Query(f), nil
}

func (b adminBackend) RequestAggregates(_ context.Context, f traffic.RequestFilter, topN int) (traffic.Aggregates, error) {
	return b.s.traffic.Requests().Aggregate(f, topN), nil
}

func (b adminBackend) Request(_ context.Context, id uint64) (traffic.Request, error) {
	r, ok := b.s.traffic.Requests().Get(id)
	if !ok {
		return traffic.Request{}, adminapi.ErrNotFound
	}
	return r, nil
}

// ReplayRequest maps the refusals of Server.ReplayRequest to admin API errors.
func (b adminBackend) ReplayRequest(ctx context.Context, id uint64) (traffic.Request, error) {
	r, err := b.s.ReplayRequest(ctx, id)
	switch {
	case errors.Is(err, ErrRequestNotFound):
		return traffic.Request{}, adminapi.ErrNotFound
	case errors.Is(err, ErrReplayRefused):
		return traffic.Request{}, &adminapi.ConflictError{Message: strings.TrimPrefix(err.Error(), ErrReplayRefused.Error()+": ")}
	}
	return r, err
}

func (b adminBackend) Connections(_ context.Context, f traffic.ConnFilter) ([]traffic.Conn, error) {
	return b.s.traffic.Conns().Query(f), nil
}

func (b adminBackend) AuthFailures(_ context.Context, since time.Time, limit int) ([]traffic.Conn, error) {
	return b.s.traffic.AuthFailures(since, limit), nil
}
