// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package client implements the porthole client: one outbound session to the server, tunnel registration,
// forwarding of data streams to local targets, and reconnection with exponential backoff.
//
// The wire format is specified in docs/protocol.md.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
)

// TunnelSpec describes one tunnel the client wants the server to expose.
type TunnelSpec struct {
	// Kind is proto.KindHTTP or proto.KindTCP.
	Kind string
	// Name is the requested tunnel name. If empty it defaults to "http-<port>" / "tcp-<port>" taken from LocalAddr.
	Name string
	// LocalAddr is the local target, "host:port".
	LocalAddr string
	// RemotePort is the requested public port (tcp only); 0 lets the server choose.
	RemotePort int
}

// Options configures Run and Check.
type Options struct {
	// ServerURL is the server base URL: "https://tun.example.com", or "http://127.0.0.1:8080" for dev servers.
	// It is converted to wss/ws plus proto.ConnectPath.
	ServerURL string
	// Token is the client token (ph_<id>_<secret>). It is never logged.
	Token string
	// Tunnels are registered in order after every (re)connect. Not used by Check.
	Tunnels []TunnelSpec
	// Version is the client version reported in hello. Empty means "dev".
	Version string
	// Logger receives diagnostics. Nil discards them.
	Logger *slog.Logger
	// TLSConfig is used for wss. Nil means the system defaults.
	TLSConfig *tls.Config
	// OnEvent, if set, is called for every Event. It is always called from the goroutine that runs Run, so it
	// needs no locking against other events, but it must not block for long.
	OnEvent func(Event)
	// MaxInitialAttempts bounds the connection attempts made before the first session is established in this
	// process: Run gives up with an *InitialConnectError once that many attempts failed, or at once when the
	// failure cannot be fixed by retrying (unknown host, TLS certificate verification). Zero or a negative value
	// means no limit. Once a session has been established (the server accepted the handshake) the limit no longer
	// applies and Run reconnects forever. DefaultMaxInitialAttempts is the value the porthole CLI uses.
	MaxInitialAttempts int
}

// DefaultMaxInitialAttempts is the default for Options.MaxInitialAttempts in the porthole CLI.
const DefaultMaxInitialAttempts = 5

// InitialConnectError is returned by Run when no session could be established: the attempt limit was reached
// or the failure is not retryable. It unwraps to the error of the last attempt.
type InitialConnectError struct {
	URL      string // WebSocket endpoint that was dialled
	Attempts int    // number of failed attempts
	Err      error  // error of the last attempt
}

func (e *InitialConnectError) Error() string {
	return fmt.Sprintf("cannot connect to %s (%d failed attempt(s)): %v", e.URL, e.Attempts, e.Err)
}

func (e *InitialConnectError) Unwrap() error { return e.Err }

// Event is a state change reported through Options.OnEvent. The concrete types are Connected, TunnelReady,
// TunnelClosed and Disconnected.
type Event interface{ isEvent() }

// Connected is emitted after the server accepted the handshake.
type Connected struct {
	// ClientName is the name of the client identity of the token, as reported by the server.
	ClientName string
}

// TunnelReady is emitted when the server registered a tunnel.
type TunnelReady struct {
	Spec      TunnelSpec // the requested tunnel, with the default name filled in
	Name      string     // effective name chosen by the server
	PublicURL string
}

// TunnelClosed is emitted when a tunnel is gone: the server dropped it, or it could not be re-registered
// after a reconnect.
type TunnelClosed struct {
	Name   string
	Reason string
}

// Disconnected is emitted when the session ended or could not be established and Run will try again.
type Disconnected struct {
	Err     error
	RetryIn time.Duration
	// Attempt is the number of the failed connection attempt (1-based) while no session has been established yet in
	// this process; it is 0 once one has. MaxAttempts is the limit in effect (Options.MaxInitialAttempts); it is
	// 0 when there is no limit.
	Attempt     int
	MaxAttempts int
}

func (Connected) isEvent()    {}
func (TunnelReady) isEvent()  {}
func (TunnelClosed) isEvent() {}
func (Disconnected) isEvent() {}

// tuning holds timeouts and limits. Tests override them; Run uses defaultTuning.
type tuning struct {
	dialTimeout      time.Duration // WebSocket dial
	handshakeTimeout time.Duration // hello -> hello_ok
	registerTimeout  time.Duration // all registrations
	writeTimeout     time.Duration // one control write
	headerTimeout    time.Duration // stream header on a data stream
	localDialTimeout time.Duration // dial of the local target
	backoffBase      time.Duration
	backoffMax       time.Duration
	stableAfter      time.Duration // a session this old resets the backoff
	maxRetryAfter    time.Duration // upper bound for server-requested waits
	heartbeatMisses  int           // ping intervals without a ping before the session is declared dead
	maxStreams       int           // concurrent data streams
}

func defaultTuning() tuning {
	return tuning{
		dialTimeout:      15 * time.Second,
		handshakeTimeout: 10 * time.Second,
		registerTimeout:  10 * time.Second,
		writeTimeout:     10 * time.Second,
		headerTimeout:    10 * time.Second,
		localDialTimeout: 10 * time.Second,
		backoffBase:      time.Second,
		backoffMax:       time.Minute,
		stableAfter:      30 * time.Second,
		maxRetryAfter:    time.Hour,
		heartbeatMisses:  3,
		maxStreams:       1024,
	}
}

// Run connects to the server, registers opts.Tunnels and forwards traffic until ctx is cancelled (it then returns
// nil) or an unrecoverable error occurs.
//
// Unrecoverable errors are returned as-is (use errors.As with *proto.Error to inspect them): a non-retryable
// server error (unauthorized, token_expired, token_revoked, unsupported_version), or a registration refused
// on the first connection (name_taken, forbidden, invalid_request, ...). Before the first session has been
// established, Run also gives up with an *InitialConnectError after Options.MaxInitialAttempts failed attempts, or
// at once on a failure that retrying cannot fix (unknown host, TLS certificate verification). Everything else,
// including losing the connection of an established session, is retried with exponential backoff and full
// jitter.
func Run(ctx context.Context, opts Options) error {
	return run(ctx, opts, defaultTuning())
}

func run(ctx context.Context, opts Options, t tuning) error {
	r, err := newRunner(opts, t, true)
	if err != nil {
		return err
	}
	return r.loop(ctx)
}

type runner struct {
	url   string
	opts  Options
	specs []TunnelSpec
	t     tuning
	log   *slog.Logger

	// Owned by the goroutine that runs loop.
	reqID      int
	registered bool // all tunnels were registered at least once
	everUp     bool // the server accepted the handshake at least once
}

func newRunner(opts Options, t tuning, needTunnels bool) (*runner, error) {
	wsURL, err := ConnectURL(opts.ServerURL)
	if err != nil {
		return nil, err
	}
	if _, err := auth.Parse(opts.Token); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	var specs []TunnelSpec
	if needTunnels {
		if specs, err = normalizeSpecs(opts.Tunnels); err != nil {
			return nil, err
		}
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &runner{url: wsURL, opts: opts, specs: specs, t: t, log: log}, nil
}

func (r *runner) emit(e Event) {
	if r.opts.OnEvent != nil {
		r.opts.OnEvent(e)
	}
}

// permanentError marks an error that must end Run even though its underlying *proto.Error is retryable in general.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func (r *runner) loop(ctx context.Context) error {
	attempt := 0
	initialFailures := 0
	for {
		var at attemptInfo
		err := r.session(ctx, &at)
		if ctx.Err() != nil {
			return nil //nolint:nilerr // cancellation is the normal way to stop; the session error is a consequence of it
		}
		if err == nil {
			err = errors.New("session ended")
		}
		if !at.connectedAt.IsZero() {
			r.everUp = true
		}
		var pe *permanentError
		if errors.As(err, &pe) {
			return pe.err
		}
		var perr *proto.Error
		var retryAfter time.Duration
		if errors.As(err, &perr) {
			if !perr.Retryable() {
				return err
			}
			retryAfter = time.Duration(max(perr.RetryAfterMS, 0)) * time.Millisecond
		}

		initialAttempt := 0
		if !r.everUp {
			initialFailures++
			initialAttempt = initialFailures
			limit := r.opts.MaxInitialAttempts
			if isPermanentDialError(err) || (limit > 0 && initialFailures >= limit) {
				return &InitialConnectError{URL: r.url, Attempts: initialFailures, Err: err}
			}
		}

		if !at.connectedAt.IsZero() && time.Since(at.connectedAt) >= r.t.stableAfter {
			attempt = 0
		}
		delay := backoffDelay(attempt, r.t.backoffBase, r.t.backoffMax)
		attempt++
		delay = max(delay, min(retryAfter, r.t.maxRetryAfter))

		r.log.Info("disconnected", "err", err, "retry_in", delay)
		ev := Disconnected{Err: err, RetryIn: delay}
		if initialAttempt > 0 {
			ev.Attempt, ev.MaxAttempts = initialAttempt, max(r.opts.MaxInitialAttempts, 0)
		}
		r.emit(ev)
		if !sleep(ctx, delay) {
			return nil
		}
	}
}

// isPermanentDialError reports whether err means that retrying the same URL cannot help: the host name does not
// exist, or the server certificate is not trusted or does not match the host.
func isPermanentDialError(err error) bool {
	var dns *net.DNSError
	if errors.As(err, &dns) && dns.IsNotFound && !dns.IsTemporary {
		return true
	}
	return IsTLSVerifyError(err)
}

// IsTLSVerifyError reports whether err is a failure to verify the server certificate.
func IsTLSVerifyError(err error) bool {
	var cve *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certErr x509.CertificateInvalidError
	return errors.As(err, &cve) || errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &certErr)
}

// backoffDelay returns a random delay in [0, min(max, base*2^attempt)) ("full jitter").
func backoffDelay(attempt int, base, maxDelay time.Duration) time.Duration {
	limit := maxDelay
	if attempt < 31 {
		if d := base << attempt; d > 0 && d < maxDelay {
			limit = d
		}
	}
	if limit <= 0 {
		return 0
	}
	return rand.N(limit) //nolint:gosec // jitter, not security-sensitive
}

func sleep(ctx context.Context, d time.Duration) bool {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-tm.C:
		return true
	}
}

// ConnectURL converts a server base URL ("https://tun.example.com") to the WebSocket endpoint
// ("wss://tun.example.com/_porthole/v1/connect"). Only http and https schemes with a host are accepted.
func ConnectURL(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("invalid server URL %q: scheme must be http or https", serverURL)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("invalid server URL %q: missing host", serverURL)
	}
	if u.User != nil {
		return "", fmt.Errorf("invalid server URL %q: credentials in the URL are not supported", serverURL)
	}
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	u.Path = trimSlash(u.Path) + proto.ConnectPath
	u.RawPath = ""
	return u.String(), nil
}

func trimSlash(p string) string {
	for len(p) > 0 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}

// normalizeSpecs validates specs and fills in default names.
func normalizeSpecs(in []TunnelSpec) ([]TunnelSpec, error) {
	if len(in) == 0 {
		return nil, errors.New("no tunnels requested")
	}
	out := make([]TunnelSpec, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, s := range in {
		if s.Kind != proto.KindHTTP && s.Kind != proto.KindTCP {
			return nil, fmt.Errorf("tunnel kind %q is not supported (want %s or %s)", s.Kind, proto.KindHTTP, proto.KindTCP)
		}
		_, port, err := net.SplitHostPort(s.LocalAddr)
		if err != nil {
			return nil, fmt.Errorf("local address %q: %w", s.LocalAddr, err)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("local address %q: invalid port", s.LocalAddr)
		}
		if s.Name == "" {
			s.Name = s.Kind + "-" + port
		}
		if !auth.ValidName(s.Name) {
			return nil, fmt.Errorf("invalid tunnel name %q: use 1-32 chars of a-z, 0-9 and '-', not starting or ending with '-'", s.Name)
		}
		if s.RemotePort < 0 || s.RemotePort > 65535 {
			return nil, fmt.Errorf("invalid remote port %d", s.RemotePort)
		}
		if s.RemotePort != 0 && s.Kind != proto.KindTCP {
			return nil, errors.New("remote port is only valid for tcp tunnels")
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("duplicate tunnel name %q", s.Name)
		}
		seen[s.Name] = true
		out = append(out, s)
	}
	return out, nil
}
