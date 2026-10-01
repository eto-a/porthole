// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// acmeManager obtains and renews certificates on demand (TLS mode "acme", ADR 0004) with certmagic, the library
// behind Caddy's on_demand_tls. The abuse guard is Server.allowCertName.
type acmeManager struct {
	magic  *certmagic.Config
	issuer *certmagic.ACMEIssuer
	cache  *certmagic.Cache
}

// newACME builds the certmagic configuration: certificates and the ACME account live in <data_dir>/certs,
// TLS-ALPN-01 and HTTP-01 are enabled, and only names accepted by allowCertName are ever requested.
func (s *Server) newACME() (*acmeManager, error) {
	dir := filepath.Join(s.cfg.DataDir, "certs")
	if err := ensurePrivateDir(dir, s.log); err != nil {
		return nil, fmt.Errorf("server: acme: %w", err)
	}
	zl := zap.New(&zapSlogCore{log: s.log.With("component", "acme")})

	m := &acmeManager{}
	m.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return m.magic, nil },
		Logger:           zl,
	})
	m.magic = certmagic.New(m.cache, certmagic.Config{
		Storage:  &certmagic.FileStorage{Path: dir},
		OnDemand: &certmagic.OnDemandConfig{DecisionFunc: s.allowCertName},
		OnEvent:  s.onACMEEvent,
		Logger:   zl,
	})
	tmpl := certmagic.ACMEIssuer{
		CA:     s.cfg.TLS.ACME.CAURL(),
		Email:  s.cfg.TLS.ACME.Email,
		Agreed: true,
		Logger: zl,
	}
	// Our own listeners may sit on non-standard ports (behind a port-mapping proxy). Telling certmagic the
	// ports makes it recognise them as busy instead of trying to bind :80 and :443 itself.
	if p := portOf(s.cfg.HTTPListenAddr()); p != 0 {
		tmpl.AltHTTPPort = p
	}
	if p := portOf(s.cfg.Listen); p != 0 {
		tmpl.AltTLSALPNPort = p
	}
	m.issuer = certmagic.NewACMEIssuer(m.magic, tmpl)
	m.magic.Issuers = []certmagic.Issuer{m.issuer}
	s.certBudget.exists = m.hasCert
	return m, nil
}

// tlsConfig is the HTTPS listener configuration. HTTP/1.1 only, as for files mode: WebSocket upgrades need
// connection hijacking, which HTTP/2 does not offer. certmagic adds acme-tls/1 for TLS-ALPN-01.
func (m *acmeManager) tlsConfig() *tls.Config {
	c := m.magic.TLSConfig()
	c.MinVersion = tls.VersionTLS12
	c.NextProtos = slices.Insert(c.NextProtos, 0, "http/1.1")
	return c
}

func (m *acmeManager) close() { m.cache.Stop() }

// allowCertName is certmagic's DecisionFunc and the in-process equivalent of Caddy's `ask` endpoint: a certificate
// is requested only for the control host <domain> and for <label>.<domain> where label belongs to a live tunnel
// or to one whose client disconnected within the offline grace period. Everything else (unknown labels, nested
// names, other domains, IP addresses) fails the handshake without contacting the CA.
func (s *Server) allowCertName(ctx context.Context, name string) error {
	host := normalizeHost(name)
	if host == s.domain {
		return nil
	}
	label, ok := s.labelOf(host)
	if !ok {
		s.log.Warn("certificate refused: name is not the control host or a tunnel host", "host", name)
		return errors.New("name is not served by this server")
	}
	if !s.labelKnown(label) {
		s.log.Warn("certificate refused: no live tunnel with this label", "host", name)
		return errors.New("no tunnel with this label")
	}
	if err := s.certBudget.allow(ctx, host, s.labelClient(label), s.now()); err != nil {
		s.log.Warn("certificate refused: issuance budget", "host", name, "err", err)
		return fmt.Errorf("certificate budget: %w", err)
	}
	return nil
}

// labelKnown reports whether label belongs to a live tunnel or to one still inside the offline grace period.
func (s *Server) labelKnown(label string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.labels[label] != nil {
		return true
	}
	exp, ok := s.offline[label]
	return ok && s.now().Before(exp)
}

// redirectHandler serves the plain-HTTP listener: /healthz as on the main listener, and a 301 to the same
// host and path over https for the control host and known tunnel hosts. Other hosts get 404, so the listener is
// not an open redirector for arbitrary Host headers. Forwarded-* headers are not consulted: the scheme of
// this listener is always http.
func (s *Server) redirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeHost(r.Host)
		if r.URL.Path == healthPath && !strings.HasSuffix(host, "."+s.domain) {
			serveHealth(w)
			return
		}
		if label, isLabel := s.labelOf(host); host != s.domain && (!isLabel || !s.labelKnown(label)) {
			http.NotFound(w, r)
			return
		}
		target := host
		if p := s.cfg.PublicPort; p != 0 && p != 443 {
			target = net.JoinHostPort(host, strconv.Itoa(p))
		}
		//nolint:gosec // target is the control host or a known tunnel host, checked above
		http.Redirect(w, r, "https://"+target+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

// portOf returns the numeric port of a listen address, or 0 if there is none or it is the standard one.
func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n == 80 || n == 443 {
		return 0
	}
	return n
}

// startHTTPListener serves h on the plain-HTTP address (challenge handler plus redirect). The returned stop
// function shuts it down within grace and is safe to call more than once.
func (s *Server) startHTTPListener(ctx context.Context, addr string, h http.Handler) (stop func(grace context.Context), err error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("server: listen %s: %w", addr, err)
	}
	if ln, err = s.wrapProxyIf(ln, s.cfg.ProxyProtocol && s.cfg.ProxyProtocolHTTP); err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	if !s.start(func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("http listener stopped", "addr", addr, "err", err)
		}
	}) {
		_ = ln.Close()
		return nil, errors.New("server: closed")
	}
	s.log.Info("http listener started (ACME HTTP-01 and https redirect)", "addr", ln.Addr().String())
	return func(grace context.Context) {
		if err := srv.Shutdown(grace); err != nil {
			_ = srv.Close()
		}
	}, nil
}

// zapSlogCore forwards certmagic's zap log entries to our slog logger.
type zapSlogCore struct {
	log    *slog.Logger
	fields []zapcore.Field
}

func slogLevel(l zapcore.Level) slog.Level {
	switch {
	case l <= zapcore.DebugLevel:
		return slog.LevelDebug
	case l == zapcore.InfoLevel:
		return slog.LevelInfo
	case l == zapcore.WarnLevel:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

func (c *zapSlogCore) Enabled(l zapcore.Level) bool {
	return c.log.Enabled(context.Background(), slogLevel(l))
}

func (c *zapSlogCore) With(f []zapcore.Field) zapcore.Core {
	return &zapSlogCore{log: c.log, fields: append(slices.Clone(c.fields), f...)}
}

func (c *zapSlogCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *zapSlogCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range c.fields {
		f.AddTo(enc)
	}
	for _, f := range fields {
		f.AddTo(enc)
	}
	keys := make([]string, 0, len(enc.Fields))
	for k := range enc.Fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	attrs := make([]any, 0, 2*len(keys)+2)
	if e.LoggerName != "" {
		attrs = append(attrs, "logger", e.LoggerName)
	}
	for _, k := range keys {
		attrs = append(attrs, k, enc.Fields[k])
	}
	c.log.Log(context.Background(), slogLevel(e.Level), e.Message, attrs...) //nolint:sloglint // forwarding certmagic messages
	return nil
}

func (c *zapSlogCore) Sync() error { return nil }
