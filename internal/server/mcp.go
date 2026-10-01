// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"

	mcpserver "github.com/eto-a/porthole/internal/mcp/server"
)

// newMCPHandler builds the operator MCP endpoint (ADR 0005, surface A) over this server's registry, store and
// traffic log. It authenticates with the same rules and per-IP failure limiter as the admin API.
func (s *Server) newMCPHandler() (http.Handler, error) {
	return mcpserver.NewHTTPHandler(
		&mcpserver.LocalOps{Backend: adminBackend{s}, Store: s.store, Traffic: s.traffic, ServerURL: s.cfg.PublicURL(), MaxTunnelsPerClient: s.cfg.MaxTunnelsPerClient, Now: s.now},
		mcpserver.Options{Audit: s.store, Now: s.now, Logger: s.log, Version: s.version},
		mcpserver.HTTPOptions{
			Authenticate: s.adminAuthenticate,
			ClientIP:     func(r *http.Request) string { return ipOf(visitorAddr(r, s.cfg.TrustProxyHeaders)) },
			Logger:       s.log,
		})
}

// serveMCP handles mcpserver.Path on the control host.
func (s *Server) serveMCP(w http.ResponseWriter, r *http.Request) {
	if s.ctx.Err() != nil {
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
		return
	}
	s.mcpHandler.ServeHTTP(w, r)
}
