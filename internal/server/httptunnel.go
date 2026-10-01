// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// visitorKey carries the visitor's address from the proxy's Rewrite to the transport's DialContext.
type visitorKey struct{}

const (
	httpIdleConnTimeout = 60 * time.Second
	httpMaxIdlePerHost  = 16
)

// initHTTPTunnel prepares the reverse proxy of an HTTP tunnel. Each tunnel has its own transport whose dialer
// opens a data stream to the owning client, so requests can only ever reach that client: the tunnel is looked
// up by Host, and that same object carries the route (DESIGN.md §3.5).
func (s *Server) initHTTPTunnel(t *tunnel) {
	c := t.sess
	target := &url.URL{Scheme: "http", Host: t.label}

	t.tr = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			remote, _ := ctx.Value(visitorKey{}).(string)
			return c.openStream(ctx, t.id, remote)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          2 * httpMaxIdlePerHost,
		MaxIdleConnsPerHost:   httpMaxIdlePerHost,
		IdleConnTimeout:       httpIdleConnTimeout,
		ResponseHeaderTimeout: httpResponseHeaderTimout,
		DisableCompression:    true, // pass Accept-Encoding and the body through untouched
	}
	t.handler = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			remote := s.visitorAddr(pr.In)
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // the backend sees the hostname the visitor used
			// ReverseProxy has already dropped every Forwarded/X-Forwarded-* header the visitor sent;
			// SetXForwarded writes our own values.
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Proto", s.cfg.PublicScheme)
			if s.cfg.TrustProxyHeaders {
				pr.Out.Header.Set("X-Forwarded-For", ipOf(remote))
			}
			pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), visitorKey{}, remote))
		},
		Transport: t.tr,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if !errors.Is(err, context.Canceled) {
				c.log.Debug("tunnel request failed", "tunnel", t.id, "host", r.Host, "err", err)
			}
			if bodyStalled(r) {
				w.Header().Set("Connection", "close")
				http.Error(w, "request body timed out", http.StatusRequestTimeout)
				return
			}
			http.Error(w, "bad gateway: the tunnel client did not answer", http.StatusBadGateway)
		},
	}
}
