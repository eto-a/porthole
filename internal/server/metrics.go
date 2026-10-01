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

	"github.com/eto-a/porthole/internal/metrics"
)

// metricsState reports live sessions and tunnels for the porthole_sessions and porthole_tunnels gauges. It is
// read at every scrape, so the gauges follow the registry without any hook on the registration paths.
func (s *Server) metricsState() metrics.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := metrics.State{Tunnels: make(map[string]int)}
	for _, c := range s.sessions {
		if c.dead {
			continue
		}
		st.Sessions++
		for _, t := range c.tunnels {
			st.Tunnels[t.kind]++
		}
	}
	return st
}

// startMetricsListener listens on cfg.MetricsListen when it is set and serves /metrics and /debug/pprof/ there.
func (s *Server) startMetricsListener(ctx context.Context) error {
	if s.cfg.MetricsListen == "" {
		return nil
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("server: metrics listen %s: %w", s.cfg.MetricsListen, err)
	}
	return s.StartMetricsListener(ln)
}

// StartMetricsListener serves /metrics and /debug/pprof/ on ln in the background until the server closes. It takes
// ownership of ln. The endpoints are unauthenticated, so a listener that is not on a loopback address is logged
// as a warning (it is the operator's call, for example behind a firewall or a private network).
func (s *Server) StartMetricsListener(ln net.Listener) error {
	if s.metrics == nil {
		_ = ln.Close()
		return errors.New("server: metrics are not enabled")
	}
	if !isLoopback(ln.Addr()) {
		s.log.Warn("metrics listener is not bound to a loopback address; /metrics and /debug/pprof are unauthenticated",
			"addr", ln.Addr().String())
	}
	// No WriteTimeout: /debug/pprof/profile and /trace stream for as long as the caller asks.
	srv := &http.Server{
		Handler:           s.metrics.Handler(),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	if !s.start(func() {
		stop := context.AfterFunc(s.ctx, func() { _ = srv.Close() })
		defer stop()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("metrics listener stopped", "addr", ln.Addr().String(), "err", err)
		}
	}) {
		_ = ln.Close()
		return errors.New("server: closed")
	}
	s.log.Info("metrics listener started", "addr", ln.Addr().String())
	return nil
}

// isLoopback reports whether addr is a TCP address on a loopback IP. The unspecified address (":9090") is not.
func isLoopback(addr net.Addr) bool {
	ta, ok := addr.(*net.TCPAddr)
	return ok && ta.IP.IsLoopback()
}

// onACMEEvent is certmagic's OnEvent callback; it only counts certificate results.
func (s *Server) onACMEEvent(_ context.Context, event string, _ map[string]any) error {
	switch event {
	case "cert_obtained":
		s.metrics.ACMEResult(metrics.ACMEObtained)
	case "cert_failed":
		s.metrics.ACMEResult(metrics.ACMEFailed)
	}
	return nil
}
