// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/store"
)

// Path is where the Streamable HTTP endpoint is served, on the control host only.
const Path = "/_porthole/mcp"

// maxRequestBytes bounds one JSON-RPC message; tool arguments are tiny.
const maxRequestBytes = 64 << 10

// HTTPOptions configures NewHTTPHandler.
type HTTPOptions struct {
	// Authenticate resolves a bearer secret to an active token, like adminapi.Options.Authenticate: it returns
	// adminapi.ErrUnauthorized, *adminapi.RateLimitedError or another error (HTTP 500). Required.
	Authenticate func(ctx context.Context, ip, raw string) (*store.Token, error)
	// ClientIP extracts the caller's address, for rate limiting. Default: the host of RemoteAddr.
	ClientIP func(r *http.Request) string
	Logger   *slog.Logger
}

type tokenKey struct{}

// NewHTTPHandler serves the MCP tools over Streamable HTTP. Every request needs a bearer token; the scopes of the
// token are checked on every tool call, and mutating calls are audited with the token id as actor (opts.Audit).
// The server is stateless: each request is authenticated on its own, so a revoked token stops working at once and
// there are no sessions to leak.
func NewHTTPHandler(ops Ops, opts Options, h HTTPOptions) (http.Handler, error) {
	if h.Authenticate == nil {
		return nil, errors.New("mcp server: Authenticate is required")
	}
	if h.Logger == nil {
		h.Logger = slog.New(slog.DiscardHandler)
	}
	if h.ClientIP == nil {
		h.ClientIP = func(r *http.Request) string {
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				return host
			}
			return r.RemoteAddr
		}
	}
	opts.RequireAuth = true
	srv, err := New(ops, opts)
	if err != nil {
		return nil, err
	}
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
		Logger:       h.Logger,
		// The endpoint is reached through a reverse proxy or directly, so the Host header says nothing about the
		// peer, and a bearer token (not a cookie) authenticates every request: DNS rebinding gains nothing.
		DisableLocalhostProtection: true,
		MaxRequestBodyBytes:        maxRequestBytes,
	})
	// The SDK's middleware copies the token's scopes and id into the context of each tool call.
	verify := func(ctx context.Context, _ string, _ *http.Request) (*auth.TokenInfo, error) {
		tok, _ := ctx.Value(tokenKey{}).(*store.Token)
		if tok == nil {
			return nil, auth.ErrInvalidToken
		}
		ti := &auth.TokenInfo{Scopes: tok.Scopes, UserID: tok.ID}
		if tok.ExpiresAt != nil {
			ti.Expiration = *tok.ExpiresAt
		}
		return ti, nil
	}
	inner := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(mcpHandler)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="porthole-mcp"`)
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		tok, err := h.Authenticate(r.Context(), h.ClientIP(r), raw)
		var rl *adminapi.RateLimitedError
		switch {
		case errors.As(err, &rl):
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int((rl.RetryAfter+time.Second-1)/time.Second))))
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		case errors.Is(err, adminapi.ErrUnauthorized):
			w.Header().Set("WWW-Authenticate", `Bearer realm="porthole-mcp", error="invalid_token"`)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		case err != nil:
			h.Logger.Error("mcp authentication failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenKey{}, tok)))
	}), nil
}

func bearer(h string) (string, bool) {
	scheme, raw, ok := strings.Cut(h, " ")
	raw = strings.TrimSpace(raw)
	if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" {
		return "", false
	}
	return raw, true
}
