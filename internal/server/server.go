// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package server implements portholed: it accepts client sessions over WebSocket+yamux (docs/protocol.md),
// keeps the registry of tunnels and routes public HTTP and TCP traffic into them (DESIGN.md §3.5).
//
// Every client session owns a context. Closing a session releases its tunnels, closes its listeners, streams
// and transports and waits for every goroutine it started. Server.Close does the same for all sessions.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eto-a/porthole/internal/config"
	mcpserver "github.com/eto-a/porthole/internal/mcp/server"
	"github.com/eto-a/porthole/internal/metrics"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/traffic"
	"github.com/eto-a/porthole/internal/transport"
)

// Defaults and hard limits.
const (
	defaultHandshakeTimeout  = 10 * time.Second
	defaultRevalidateEvery   = 30 * time.Second
	writeTimeout             = 5 * time.Second
	storeTimeout             = 5 * time.Second
	maxMissedPongs           = 3
	reservationTTL           = 24 * time.Hour
	offlineGrace             = 2 * time.Minute
	maxTCPConnsPerTunnel     = 1024
	httpReadHeaderTimeout    = 10 * time.Second
	httpIdleTimeout          = 120 * time.Second
	httpMaxHeaderBytes       = 64 << 10
	httpResponseHeaderTimout = 2 * time.Minute

	// Defaults of config.Limits.
	defaultMaxConnsPerIP              = 32
	defaultTCPIdleTimeout             = 2 * time.Hour
	defaultMaxHTTPRequests            = 512
	defaultHTTPBodyIdleTimeout        = time.Minute
	defaultMaxPendingHandshakes       = 256
	maxPendingPerIP                   = 8 // default of config.Limits.MaxPendingHandshakesPerIP
	halfClosedIdleTimeout             = 5 * time.Minute
	defaultNewNamesPerDay             = 30
	defaultLabelClaimTTL              = 30 * 24 * time.Hour
	minLabelClaimsPerClient           = 40          // floor of the default of config.Limits.MaxLabelClaimsPerClient
	labelSweepEvery                   = time.Hour   // lazy sweep of unused label claims, from registrations
	labelForcedSweepEvery             = time.Minute // sweep when a client hits its label claim limit
	maxNewNamesPerClientPerHour       = 10          // default of config.ACME.MaxNewNamesPerClientPerHour
	preAuthByteBudget           int64 = 128 << 10   // bytes an unauthenticated peer may send before hello_ok
)

// Options configures a Server.
type Options struct {
	Config  *config.Config
	Store   store.Store
	Logger  *slog.Logger
	Version string
	// Now returns the current time; nil means time.Now. Tests use it to move token expiry.
	Now func() time.Time

	// The fields below tune timings and exist for tests; zero values select the documented defaults.

	// HeartbeatInterval is the ping period (default proto.DefaultHBMilli ms).
	HeartbeatInterval time.Duration
	// RevalidateInterval is how often tokens of live sessions are re-read from the store (default 30 s).
	RevalidateInterval time.Duration
	// HandshakeTimeout bounds session establishment (default 10 s).
	HandshakeTimeout time.Duration
	// RemoteOpenTimeout bounds the wait for a client's answer to a remote tunnel request (default 15 s).
	RemoteOpenTimeout time.Duration

	// SSHIdleTimeout closes SSH gateway connections without open channels after this long (default 60 s).
	SSHIdleTimeout time.Duration

	// Metrics receives the Prometheus instrumentation. Nil turns it off, unless cfg.MetricsListen is set: then
	// the server creates its own.
	Metrics *metrics.Metrics
}

// Server is the portholed core. Create it with New and always release it with Close (Run and Serve do so).
type Server struct {
	cfg     *config.Config
	store   store.Store
	log     *slog.Logger
	version string
	now     func() time.Time
	started time.Time

	adminBearer http.Handler // admin API for the control host, bearer token required
	adminSocket http.Handler // admin API for the unix socket, no token
	mcpHandler  http.Handler // operator MCP endpoint for the control host, bearer token required

	domain         string
	portLo, portHi int
	hb             time.Duration
	revalidate     time.Duration
	hsTimeout      time.Duration
	openTimeout    time.Duration
	sshIdle        time.Duration // gateway connections without channels are closed after this
	limiter        *failLimiter
	trustedNets    []netip.Prefix // trusted_proxies, parsed
	pending        *ipCounter     // control connections that have not authenticated yet
	tcpConns       *ipCounter     // visitor connections to TCP tunnels, per source IP
	sshConns       *ipCounter     // SSH gateway connections, per source IP
	tcpIdle        time.Duration  // idle timeout of piped connections; 0 = none
	tcpHalfClose   time.Duration  // silence allowed after one side half-closed; 0 = none; independent of tcpIdle
	httpMaxReqs    int            // simultaneous requests per HTTP tunnel; 0 = unlimited
	bodyIdle       time.Duration  // stall timeout of visitor request bodies; 0 = none
	claimTTL       time.Duration  // unused label claims older than this are deleted; 0 = never
	maxClaims      int            // label claims per client; 0 = unlimited
	lastSweep      atomic.Int64   // unix nanoseconds of the last label claim sweep
	certBudget     *certBudget    // new-certificate budget (ACME mode)
	traffic        *traffic.Log
	metrics        *metrics.Metrics // nil = off; every hook is nil-safe

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // every session goroutine
	// persist runs the store writes the registry does not wait for; Close drains it.
	persist *persister

	mu        sync.Mutex // guards everything below and the tunnel maps of every session
	closed    bool
	certs     *certReloader          // nil until Serve has loaded the TLS certificate (and always nil without TLS)
	sessions  map[string]*session    // by client name
	labels    map[string]*tunnel     // HTTP tunnels by DNS label
	ports     map[int]*tunnel        // live TCP tunnels by public port
	sshLabels map[string]*tunnel     // live ssh tunnels by gateway label "<tunnel>-<client>"
	reserved  map[string]reservation // released TCP ports by "client/tunnel"
	offline   map[string]time.Time   // labels of tunnels whose client just went away, until expiry
	held      map[string]hold        // addresses (see addrKey) kept for the owner of a tunnel that just went away
}

// New validates opts and returns a Server. It starts nothing.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("server: Config is required")
	}
	if opts.Store == nil {
		return nil, errors.New("server: Store is required")
	}
	if err := opts.Config.Validate(); err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	lo, hi, err := opts.Config.PortRange()
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	lim := opts.Config.Limits
	s := &Server{
		trustedNets: parseTrustedProxies(opts.Config.TrustedProxies),
		pending: newIPCounter(
			limitOrDefault(lim.MaxPendingHandshakesPerIP, maxPendingPerIP),
			limitOrDefault(lim.MaxPendingHandshakes, defaultMaxPendingHandshakes)),
		tcpConns:     newIPCounter(limitOrDefault(lim.MaxConnsPerIP, defaultMaxConnsPerIP), 0),
		sshConns:     newIPCounter(limitOrDefault(lim.MaxConnsPerIP, defaultMaxConnsPerIP), 0),
		tcpIdle:      durationOrDefault(lim.TCPIdleTimeout, defaultTCPIdleTimeout),
		tcpHalfClose: durationOrDefault(lim.TCPHalfCloseTimeout, halfClosedIdleTimeout),
		httpMaxReqs:  limitOrDefault(lim.MaxHTTPRequestsPerTunnel, defaultMaxHTTPRequests),
		bodyIdle:     durationOrDefault(lim.HTTPBodyIdleTimeout, defaultHTTPBodyIdleTimeout),
		claimTTL:     durationOrDefault(lim.LabelClaimTTL, defaultLabelClaimTTL),
		maxClaims: limitOrDefault(lim.MaxLabelClaimsPerClient,
			max(minLabelClaimsPerClient, 4*opts.Config.MaxTunnelsPerClient)),
		certBudget:  newCertBudget(opts.Config.TLS.ACME),
		cfg:         opts.Config,
		store:       opts.Store,
		persist:     newPersister(storeTimeout),
		log:         opts.Logger,
		version:     opts.Version,
		now:         opts.Now,
		domain:      normalizeHost(opts.Config.Domain),
		portLo:      lo,
		portHi:      hi,
		hb:          opts.HeartbeatInterval,
		revalidate:  opts.RevalidateInterval,
		hsTimeout:   opts.HandshakeTimeout,
		openTimeout: opts.RemoteOpenTimeout,
		sshIdle:     opts.SSHIdleTimeout,
		limiter:     newFailLimiter(),
		traffic:     newTrafficLog(opts.Config.Traffic),
		metrics:     opts.Metrics,
		sessions:    make(map[string]*session),
		labels:      make(map[string]*tunnel),
		ports:       make(map[int]*tunnel),
		sshLabels:   make(map[string]*tunnel),
		reserved:    make(map[string]reservation),
		offline:     make(map[string]time.Time),
		held:        make(map[string]hold),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.hb <= 0 {
		s.hb = proto.DefaultHBMilli * time.Millisecond
	}
	if s.revalidate <= 0 {
		s.revalidate = defaultRevalidateEvery
	}
	if s.openTimeout <= 0 {
		s.openTimeout = defaultRemoteOpenTimeout
	}
	if s.sshIdle <= 0 {
		s.sshIdle = defaultSSHIdleTimeout
	}
	if s.hsTimeout <= 0 {
		s.hsTimeout = defaultHandshakeTimeout
	}
	s.started = s.now()
	api, err := s.newAdminAPI()
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	s.adminBearer, s.adminSocket = api.BearerHandler(), api.SocketHandler()
	if s.mcpHandler, err = s.newMCPHandler(); err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	if s.metrics == nil && s.cfg.MetricsListen != "" {
		s.metrics = metrics.New(s.version)
	}
	s.metrics.SetStateSource(s.metricsState)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.loadReservations()
	s.sweepLabelClaims(0)
	return s, nil
}

// Handler returns the HTTP handler for the public listener: the control endpoint, /healthz and the virtual
// hosts of HTTP tunnels.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

// Run listens on cfg.Listen (TLS when configured) and serves until ctx is done, then shuts down gracefully
// within cfg.ShutdownGrace and closes every session and TCP listener.
func (s *Server) Run(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("server: listen %s: %w", s.cfg.Listen, err)
	}
	return s.Serve(ctx, ln)
}

// Serve is Run on an existing listener. It takes ownership of ln.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer func() { _ = s.Close() }()
	tightenDir(s.cfg.DataDir, s.log)
	s.warnSharedAddresses()

	// PROXY protocol is parsed below TLS, so wrap the raw listener first.
	ln, err := s.wrapProxyIf(ln, s.cfg.ProxyProtocol)
	if err != nil {
		return err
	}
	if err := s.startSSHGateway(ctx); err != nil {
		_ = ln.Close()
		return err
	}
	if err := s.startAdminSocket(ctx); err != nil {
		_ = ln.Close()
		return err
	}
	if err := s.startMetricsListener(ctx); err != nil {
		_ = ln.Close()
		return err
	}

	var am *acmeManager
	switch s.cfg.TLS.EffectiveMode() {
	case config.TLSModeFiles:
		cr, err := newCertReloader(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile, s.log, s.now)
		if err != nil {
			_ = ln.Close()
			return err
		}
		s.mu.Lock()
		s.certs = cr
		s.mu.Unlock()
		// HTTP/1.1 only: WebSocket upgrades need connection hijacking, which HTTP/2 does not offer.
		ln = tls.NewListener(ln, &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"http/1.1"},
			GetCertificate: cr.get,
		})
	case config.TLSModeACME:
		var err error
		if am, err = s.newACME(); err != nil {
			_ = ln.Close()
			return err
		}
		defer am.close()
		ln = tls.NewListener(ln, am.tlsConfig())
	}

	stopHTTP := func(context.Context) {}
	if addr := s.cfg.HTTPListenAddr(); addr != "" {
		h := s.redirectHandler()
		if am != nil {
			h = am.issuer.HTTPChallengeHandler(h)
		}
		stop, err := s.startHTTPListener(ctx, addr, h)
		if err != nil {
			_ = ln.Close()
			return err
		}
		stopHTTP = stop
		defer func() { // error paths: close at once (a cancelled context makes Shutdown fall back to Close)
			dead, cancel := context.WithCancel(context.Background())
			cancel()
			stop(dead)
		}()
	}

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
		ErrorLog:          httpErrorLog(s.log),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("server: serve: %w", err)
	case <-ctx.Done():
	}

	s.log.Info("shutting down", "grace", s.cfg.ShutdownGrace)
	gctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGrace)
	defer cancel()
	stopHTTP(gctx)
	if err := srv.Shutdown(gctx); err != nil {
		s.log.Warn("graceful shutdown incomplete, closing connections", "err", err)
		_ = srv.Close()
	}
	<-errc
	return s.Close()
}

// ReloadTLS re-reads the TLS certificate and key files immediately instead of waiting for the periodic
// modification-time check; portholed calls it on SIGHUP. A failed reload keeps the previous certificate. The
// outcome is logged here; the error is returned for callers that want to react to it. It fails when TLS is not
// configured or Serve has not loaded the certificate yet.
func (s *Server) ReloadTLS() error {
	s.mu.Lock()
	cr := s.certs
	s.mu.Unlock()
	if cr == nil {
		err := errors.New("server: tls certificate reload: TLS is not enabled or the server has not started yet")
		s.log.Warn("tls certificate reload skipped", "err", err)
		return err
	}
	return cr.reload("sighup")
}

// Close ends every session (clients receive a shutting_down error), closes all TCP listeners and transports
// and waits for all goroutines started by the server. It is safe to call more than once.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
	if !s.persist.flush(persistDrainTimeout) {
		s.log.Warn("store writes still pending at shutdown were dropped", "timeout", persistDrainTimeout)
	}
	return nil
}

// start runs fn in a tracked goroutine unless the server is closed.
func (s *Server) start(fn func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Go(fn)
	return true
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	if host == s.domain {
		s.serveControl(w, r)
		return
	}
	if label, ok := s.labelOf(host); ok {
		s.metrics.InstrumentHTTP(w, r, func(w http.ResponseWriter) { s.serveTunnel(w, r, label) })
		return
	}
	// Load balancers and orchestrators probe by IP, with no usable Host. Hosts outside our domain get /healthz
	// as well; anything inside it (a deeper name such as a.b.<domain>) stays a 404.
	if r.URL.Path == healthPath && !strings.HasSuffix(host, "."+s.domain) {
		serveHealth(w)
		return
	}
	http.NotFound(w, r)
}

// healthPath is the liveness endpoint. It is answered on the bare domain and on any Host that is not under the
// domain; on <label>.<domain> the path belongs to the tunnelled application.
const healthPath = "/healthz"

func serveHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok")
}

// labelOf returns the tunnel label if host is exactly <label>.<domain>.
func (s *Server) labelOf(host string) (string, bool) {
	label, ok := strings.CutSuffix(host, "."+s.domain)
	if !ok || label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return label, true
}

func (s *Server) serveControl(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == proto.ConnectPath:
		s.handleConnect(w, r)
	case r.URL.Path == healthPath:
		serveHealth(w)
	case isAdminPath(r.URL.Path):
		s.serveAdmin(w, r)
	case r.URL.Path == proto.JoinPath:
		s.handleJoin(w, r)
	case isJoinPage(r.URL.Path):
		s.serveJoinPage(w, r)
	case r.URL.Path == mcpserver.Path:
		s.serveMCP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if s.ctx.Err() != nil {
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
		return
	}
	addr := s.visitorAddr(r)
	ip := ipOf(addr)
	// Unauthenticated sessions cost goroutines, buffers and a file descriptor each: cap them per source and overall
	// before upgrading, so an anonymous peer cannot pile them up.
	if !s.pending.acquire(ip) {
		s.log.Warn("connection refused: too many unauthenticated sessions", "ip", ip)
		w.Header().Set("Retry-After", "5")
		http.Error(w, "too many pending connections", http.StatusServiceUnavailable)
		return
	}
	ts, err := transport.AcceptWebSocketGated(w, r, hostAddr(addr), preAuthByteBudget) // writes the HTTP error itself on failure
	if err != nil {
		s.pending.release(ip)
		s.log.Debug("websocket accept failed", "remote", addr, "err", err)
		return
	}
	if !s.start(func() { s.runSession(ts, ip) }) {
		s.pending.release(ip)
		_ = ts.Close()
	}
}

// serveTunnel proxies a visitor request into the tunnel owning label.
func (s *Server) serveTunnel(w http.ResponseWriter, r *http.Request, label string) {
	s.mu.Lock()
	t := s.labels[label]
	offline := false
	if t == nil {
		if exp, ok := s.offline[label]; ok && s.now().Before(exp) {
			offline = true
		}
	}
	s.mu.Unlock()

	switch {
	case t != nil:
		release := t.acquireHTTP()
		if release == nil {
			t.sess.log.Warn("http tunnel at its request limit", "tunnel", t.id, "limit", cap(t.httpSem))
			w.Header().Set("Retry-After", "1")
			http.Error(w, "tunnel is busy", http.StatusServiceUnavailable)
			return
		}
		defer release()
		r = s.limitBody(w, r)
		s.serveRecorded(t, w, r)
	case offline:
		if reqs := s.traffic.Requests(); reqs.Enabled() {
			reqs.Add(s.requestEntry(r, s.now(), http.StatusBadGateway, 0, 0, 0, nil))
		}
		http.Error(w, "tunnel client is offline", http.StatusBadGateway)
	default:
		http.NotFound(w, r)
	}
}
