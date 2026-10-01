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
	// Kind is proto.KindHTTP, proto.KindTCP or proto.KindSSH.
	Kind string
	// Name is the requested tunnel name. If empty it defaults to "http-<port>" / "tcp-<port>" taken from LocalAddr,
	// and to "ssh" for an ssh tunnel.
	Name string
	// LocalAddr is the local target, "host:port".
	LocalAddr string
	// RemotePort is the requested public port (tcp only); 0 lets the server choose.
	RemotePort int
	// Private (ssh only) asks the gateway to require a porthole token. A server that does not confirm it is an
	// error: the tunnel is never left public silently.
	Private bool
	// Inspect (http only) asks the server to store request and response bodies and headers of the tunnel for the
	// inspector and replay. A server that refuses it fails the registration.
	Inspect bool
}

// Options configures Run and Check.
type Options struct {
	// ServerURL is the server base URL: "https://tun.example.com", or "http://127.0.0.1:8080" for dev servers.
	// It is converted to wss/ws plus proto.ConnectPath.
	ServerURL string
	// Token is the client token (ph_<id>_<secret>). It is never logged.
	Token string
	// Tunnels are registered in order after every (re)connect. Not used by Check. Run requires at least one;
	// NewManager accepts an empty set (tunnels can be added later with Manager.Add).
	Tunnels []TunnelSpec
	// Version is the client version reported in hello. Empty means "dev".
	Version string
	// Logger receives diagnostics. Nil discards them.
	Logger *slog.Logger
	// TLSConfig is used for wss. Nil means the system defaults.
	TLSConfig *tls.Config
	// OnEvent, if set, is called for every Event. It is always called from the goroutine that runs Run (or
	// Manager.Run), one event at a time and in order, so it needs no locking against other events, but it must not
	// block for long. For a Manager this holds for events caused by Add, Remove and Replace as well: they are
	// queued by the calling goroutine and delivered by the Run goroutine shortly afterwards, so OnEvent is never
	// invoked from the goroutine that called Add. It may call Manager methods: none of them blocks on OnEvent.
	OnEvent func(Event)
	// MaxInitialAttempts bounds the connection attempts made before the first session is established in this
	// process: Run gives up with an *InitialConnectError once that many attempts failed, or at once when the
	// failure cannot be fixed by retrying (unknown host, TLS certificate verification). Zero or a negative value
	// means no limit and no giving up at all, even on those failures: a daemon started before DNS works, or while
	// the server certificate is being renewed, must keep trying. Once a session has been established (the server
	// accepted the handshake) the limit no longer applies and Run reconnects forever. DefaultMaxInitialAttempts is
	// the value the porthole CLI uses.
	MaxInitialAttempts int
	// AcceptRemoteOpen announces the remote_open feature in hello: the server may then ask this client to open
	// tunnels (proto.OpenRequest), subject to RemoteOpen. Only a Manager (the daemon, `porthole start`) can serve such
	// requests; Run and Check ignore it.
	AcceptRemoteOpen bool
	// RemoteOpen limits the local targets a server request may expose. Nil permits only targets on this machine; see RemotePolicy.
	// Change it at run time with Manager.SetRemoteOpen.
	RemoteOpen *RemotePolicy
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

// Event is a state change reported through Options.OnEvent and Manager.Subscribe. The concrete types are Connected,
// TunnelReady, TunnelClosed, Disconnected, TunnelAdded and TunnelRemoved; the last two are only produced by a
// Manager when its tunnel set is changed while Run is active.
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
	SSHJump   string // host:port of the SSH gateway (ssh tunnels only)
}

// TunnelClosed is emitted when a tunnel is gone: the server dropped it (tunnel_closed), or the server refused
// to register it (after a reconnect for Run, at any time for a Manager). In a Manager the tunnel then is in state
// StatusFailed with the same reason (TunnelState.Err); it is retried on the next reconnect.
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

// TunnelAdded is emitted by a Manager running Run when a tunnel was added to its set by Add or Replace. It is
// emitted whether or not a session is up; TunnelReady follows once the server registered the tunnel.
type TunnelAdded struct {
	Spec TunnelSpec // normalized
}

// TunnelRemoved is emitted by a Manager running Run when a tunnel was removed from its set by Remove or Replace
// (a changed tunnel yields TunnelRemoved followed by TunnelAdded). The unregister message may be sent later.
type TunnelRemoved struct {
	Name string
}

func (Connected) isEvent()     {}
func (TunnelReady) isEvent()   {}
func (TunnelClosed) isEvent()  {}
func (Disconnected) isEvent()  {}
func (TunnelAdded) isEvent()   {}
func (TunnelRemoved) isEvent() {}

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
//
// Run is a Manager in strict mode: the tunnel set is fixed, and a session that ends up without any tunnel (all
// registrations refused after the first connection, or the server closed every tunnel) counts as a failed
// session and is followed by a reconnect. Use NewManager for a client whose tunnel set changes at run time.
func Run(ctx context.Context, opts Options) error {
	return run(ctx, opts, defaultTuning())
}

func run(ctx context.Context, opts Options, t tuning) error {
	m, err := newManager(opts, t, true)
	if err != nil {
		return err
	}
	return m.Run(ctx)
}

// permanentError marks an error that must end Run even though its underlying *proto.Error is retryable in general.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

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

// normalizeSpec validates one spec and fills in the default name.
func normalizeSpec(s TunnelSpec) (TunnelSpec, error) {
	if s.Kind != proto.KindHTTP && s.Kind != proto.KindTCP && s.Kind != proto.KindSSH {
		return TunnelSpec{}, fmt.Errorf("tunnel kind %q is not supported (want %s, %s or %s)", s.Kind, proto.KindHTTP, proto.KindTCP, proto.KindSSH)
	}
	_, port, err := net.SplitHostPort(s.LocalAddr)
	if err != nil {
		return TunnelSpec{}, fmt.Errorf("local address %q: %w", s.LocalAddr, err)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return TunnelSpec{}, fmt.Errorf("local address %q: invalid port", s.LocalAddr)
	}
	switch {
	case s.Name == "" && s.Kind == proto.KindSSH:
		s.Name = "ssh"
	case s.Name == "":
		s.Name = s.Kind + "-" + port
	}
	if !auth.ValidName(s.Name) {
		return TunnelSpec{}, fmt.Errorf("invalid tunnel name %q: use 1-32 chars of a-z, 0-9 and '-', not starting or ending with '-'", s.Name)
	}
	if s.RemotePort < 0 || s.RemotePort > 65535 {
		return TunnelSpec{}, fmt.Errorf("invalid remote port %d", s.RemotePort)
	}
	if s.RemotePort != 0 && s.Kind != proto.KindTCP {
		return TunnelSpec{}, errors.New("remote port is only valid for tcp tunnels")
	}
	if s.Inspect && s.Kind != proto.KindHTTP {
		return TunnelSpec{}, errors.New("inspect is only valid for http tunnels")
	}
	if s.Private && s.Kind != proto.KindSSH {
		return TunnelSpec{}, errors.New("private is only valid for ssh tunnels")
	}
	return s, nil
}

// normalizeSpecs validates a tunnel set and fills in default names. An empty set is an error.
func normalizeSpecs(in []TunnelSpec) ([]TunnelSpec, error) {
	if len(in) == 0 {
		return nil, errors.New("no tunnels requested")
	}
	return normalizeSet(in)
}

// normalizeSet is normalizeSpecs that also accepts an empty set.
func normalizeSet(in []TunnelSpec) ([]TunnelSpec, error) {
	out := make([]TunnelSpec, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, s := range in {
		s, err := normalizeSpec(s)
		if err != nil {
			return nil, err
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("duplicate tunnel name %q", s.Name)
		}
		seen[s.Name] = true
		out = append(out, s)
	}
	return out, nil
}
