// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
)

// Errors returned by the Manager methods that change the tunnel set. Use errors.Is.
var (
	// ErrTunnelExists is returned by Add when a tunnel with the same name is already in the set.
	ErrTunnelExists = errors.New("tunnel already exists")
	// ErrTunnelNotFound is returned by Remove when no tunnel has the given name.
	ErrTunnelNotFound = errors.New("tunnel not found")
	// ErrStopped is returned by Add, Remove and Replace once Run has returned.
	ErrStopped = errors.New("client manager is stopped")
	// ErrAlreadyRunning is returned by Run when it was called before; a Manager runs at most once.
	ErrAlreadyRunning = errors.New("client manager already started")
)

// ConnState is the state of the connection to the server as reported by Manager.Snapshot.
type ConnState string

// Connection states.
const (
	// ConnIdle: Run has not been called yet.
	ConnIdle ConnState = "idle"
	// ConnConnecting: dialling the server or waiting for hello_ok.
	ConnConnecting ConnState = "connecting"
	// ConnConnected: the server accepted the handshake; tunnels are being registered or are up.
	ConnConnected ConnState = "connected"
	// ConnBackoff: the last attempt or session failed; waiting until State.RetryAt.
	ConnBackoff ConnState = "backoff"
	// ConnStopped: Run has returned.
	ConnStopped ConnState = "stopped"
)

// TunnelStatus is the state of one tunnel as reported by Manager.Snapshot.
type TunnelStatus string

// Tunnel states.
const (
	// StatusPending: not registered (no session yet, or the registration is in flight).
	StatusPending TunnelStatus = "pending"
	// StatusReady: the server registered the tunnel; TunnelState.PublicURL is set.
	StatusReady TunnelStatus = "ready"
	// StatusFailed: the server refused the registration or dropped the tunnel; TunnelState.Err says why. The
	// tunnel is not retried within the same session (except by Replace, which retries failed tunnels whose spec is
	// unchanged); it is registered again after the next reconnect.
	StatusFailed TunnelStatus = "failed"
)

// TunnelState is the state of one tunnel of a Manager.
type TunnelState struct {
	Spec      TunnelSpec // normalized
	Status    TunnelStatus
	PublicURL string // set when Status is StatusReady
	// SSHJump is the host:port of the server's SSH gateway; set when Status is StatusReady for an ssh tunnel.
	SSHJump string
	// Err is set when Status is StatusFailed. For a refused registration it wraps the server's *proto.Error.
	Err error
}

// State is a consistent copy of the state of a Manager.
type State struct {
	Conn ConnState
	// ClientName is the client identity of the token as reported by the last successful handshake; empty before it.
	ClientName string
	// RetryAt is when the next connection attempt starts; set only while Conn is ConnBackoff.
	RetryAt time.Time
	// LastErr is the error that ended the last session or connection attempt; nil while connected. After Run
	// returned with an error it is that error.
	LastErr error
	// Tunnels is the whole tunnel set, sorted by name.
	Tunnels []TunnelState
}

// tunnelRec is the desired-set entry of one tunnel. Guarded by Manager.mu. A record is replaced (not mutated) when
// the spec of its name changes, so the wire side can tell a stale registration by pointer identity.
type tunnelRec struct {
	spec   TunnelSpec
	seq    int // registration order
	status TunnelStatus
	url    string
	jump   string // SSH gateway address of a ready ssh tunnel
	err    error
}

// subscriber is one Subscribe registration.
type subscriber struct{ ch chan Event }

// Manager is a client whose tunnel set can change while it is connected. It is meant for a long-running process
// (the porthole daemon); Run is the one-shot variant with a fixed set.
//
// A Manager holds one session to the server. Run connects, registers the whole set, and reconnects forever with
// the backoff of Run; after every reconnect the current set is registered again. Add, Remove, Replace, Snapshot
// and Subscribe may be called from any goroutine, before, during and after Run.
//
// Concurrency model. The goroutine that runs Run owns the connection: it is the only one that touches the wire.
// The tunnel set is a mutex-protected "desired" set; Add, Remove and Replace edit it and wake the Run goroutine,
// which reconciles the wire with the desired set (register what is missing, unregister what is stale). Changes
// therefore reach the server asynchronously: Add returns before the registration is sent; follow progress with
// Subscribe or Snapshot. A tunnel that was changed while its registration is in flight is unregistered as soon as
// the reply arrives, and only then registered with the new spec, so the server never sees two registrations of one
// name at the same time.
//
// Events are delivered from the Run goroutine only (Options.OnEvent and Subscribe), in the order of the state
// changes they describe.
type Manager struct {
	url    string
	opts   Options
	t      tuning
	log    *slog.Logger
	strict bool // v0.1 Run semantics, see newManager
	kick   chan struct{}

	mu      sync.Mutex
	desired map[string]*tunnelRec
	seq     int
	conn    ConnState
	client  string
	retryAt time.Time
	lastErr error
	started bool
	running bool // between the start and the end of Run; events are only queued while it is true
	stopped bool
	outbox  []Event // queued by state changes, delivered by flush

	subMu      sync.Mutex
	subs       map[*subscriber]struct{}
	subsClosed bool

	// Owned by the goroutine that runs Run.
	reqID   int
	regDone bool // strict mode: all tunnels were answered at least once (v0.1 "registered")
	everUp  bool // the server accepted the handshake at least once
}

// NewManager validates opts and returns a Manager that has not connected yet. opts.Tunnels is the initial tunnel
// set and may be empty. Call Run to start it.
func NewManager(opts Options) (*Manager, error) {
	return newManager(opts, defaultTuning(), false)
}

// newManager creates a Manager. strict selects the v0.1 semantics used by Run: the tunnel set must not be empty,
// a registration refused during the first full registration of the process is fatal (apart from transient server
// errors), and a session in which no tunnel is registered, or in which the server closed every tunnel, ends with
// errNoTunnels or errAllTunnelsClosed so that the tunnels are registered again after a reconnect.
func newManager(opts Options, t tuning, strict bool) (*Manager, error) {
	wsURL, err := ConnectURL(opts.ServerURL)
	if err != nil {
		return nil, err
	}
	if _, err := auth.Parse(opts.Token); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	var specs []TunnelSpec
	if strict {
		specs, err = normalizeSpecs(opts.Tunnels)
	} else {
		specs, err = normalizeSet(opts.Tunnels)
	}
	if err != nil {
		return nil, err
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if PlaintextServer(opts.ServerURL) {
		log.Warn("the server URL is plain http: the token is sent unencrypted", "server", opts.ServerURL)
	}
	m := &Manager{
		url: wsURL, opts: opts, t: t, log: log, strict: strict,
		kick:    make(chan struct{}, 1),
		desired: make(map[string]*tunnelRec, len(specs)),
		conn:    ConnIdle,
		subs:    make(map[*subscriber]struct{}),
	}
	for _, sp := range specs {
		m.addLocked(sp)
	}
	return m, nil
}

// addLocked adds a record for sp (already normalized, name not taken). m.mu must be held, or m not yet shared.
func (m *Manager) addLocked(sp TunnelSpec) {
	m.seq++
	m.desired[sp.Name] = &tunnelRec{spec: sp, seq: m.seq, status: StatusPending}
}

// postLocked queues an event for delivery by the Run goroutine. m.mu must be held. Events are queued only while
// Run is active: before it, Snapshot is the way to learn the state.
func (m *Manager) postLocked(e Event) {
	if m.running {
		m.outbox = append(m.outbox, e)
	}
}

// wake asks the Run goroutine to look at the desired set again. It never blocks.
func (m *Manager) wake() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Add adds a tunnel to the set and returns its normalized spec (default name filled in). It returns
// ErrTunnelExists (wrapped) if the name is taken and ErrStopped after Run returned. If a session is up the
// tunnel is registered right away (asynchronously), otherwise after the next connect.
func (m *Manager) Add(spec TunnelSpec) (TunnelSpec, error) {
	sp, err := normalizeSpec(spec)
	if err != nil {
		return TunnelSpec{}, err
	}
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return TunnelSpec{}, ErrStopped
	}
	if _, ok := m.desired[sp.Name]; ok {
		m.mu.Unlock()
		return TunnelSpec{}, fmt.Errorf("%w: %q", ErrTunnelExists, sp.Name)
	}
	m.addLocked(sp)
	m.postLocked(TunnelAdded{Spec: sp})
	m.mu.Unlock()
	m.wake()
	return sp, nil
}

// Remove deletes a tunnel from the set. It returns ErrTunnelNotFound (wrapped) if there is none and ErrStopped
// after Run returned. If the tunnel is registered it is unregistered at the server right away (asynchronously);
// streams already being forwarded are left to finish, new streams for it are rejected.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return ErrStopped
	}
	if _, ok := m.desired[name]; !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %q", ErrTunnelNotFound, name)
	}
	delete(m.desired, name)
	m.postLocked(TunnelRemoved{Name: name})
	m.mu.Unlock()
	m.wake()
	return nil
}

// Replace makes specs the whole tunnel set and reports the difference by tunnel name (each list is sorted). The
// change is atomic: if any spec is invalid, or two specs share a name, nothing changes. Tunnels whose normalized
// spec is identical are left alone (not re-registered); a changed tunnel is unregistered and registered again with
// the new spec. A tunnel that is in state StatusFailed and unchanged is retried, without being reported. An empty
// specs removes every tunnel. It returns ErrStopped after Run returned.
func (m *Manager) Replace(specs []TunnelSpec) (added, removed, changed []string, err error) {
	next, err := normalizeSet(specs)
	if err != nil {
		return nil, nil, nil, err
	}
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil, nil, nil, ErrStopped
	}
	want := make(map[string]TunnelSpec, len(next))
	for _, sp := range next {
		want[sp.Name] = sp
	}
	for name, rec := range m.desired {
		sp, keep := want[name]
		switch {
		case !keep:
			removed = append(removed, name)
			delete(m.desired, name)
		case sp != rec.spec:
			changed = append(changed, name)
			delete(m.desired, name)
		case rec.status == StatusFailed:
			rec.status, rec.err, rec.url = StatusPending, nil, "" // a reload retries what failed
		}
	}
	sort.Strings(removed)
	sort.Strings(changed)
	for _, name := range removed {
		m.postLocked(TunnelRemoved{Name: name})
	}
	for _, name := range changed {
		m.postLocked(TunnelRemoved{Name: name})
	}
	for _, sp := range next {
		if _, ok := m.desired[sp.Name]; ok {
			continue
		}
		if !slices.Contains(changed, sp.Name) {
			added = append(added, sp.Name)
		}
		m.addLocked(sp)
		m.postLocked(TunnelAdded{Spec: sp})
	}
	m.mu.Unlock()
	sort.Strings(added)
	m.wake()
	return added, removed, changed, nil
}

// Snapshot returns a consistent copy of the current state. It is cheap and may be called from any goroutine.
func (m *Manager) Snapshot() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := State{
		Conn:       m.conn,
		ClientName: m.client,
		RetryAt:    m.retryAt,
		LastErr:    m.lastErr,
		Tunnels:    make([]TunnelState, 0, len(m.desired)),
	}
	for _, rec := range m.desired {
		st.Tunnels = append(st.Tunnels, TunnelState{Spec: rec.spec, Status: rec.status, PublicURL: rec.url, SSHJump: rec.jump, Err: rec.err})
	}
	sort.Slice(st.Tunnels, func(i, j int) bool { return st.Tunnels[i].Spec.Name < st.Tunnels[j].Spec.Name })
	return st
}

// Subscribe returns a channel with the events of the Manager and a function that cancels the subscription and
// closes the channel (it is safe to call it more than once, and from any goroutine). The channel is also closed
// when Run returns, after the last event.
//
// Delivery never blocks Run: if the channel buffer (buf, at least 1) is full the event is dropped for this
// subscriber. Events are therefore hints; the truth is Snapshot, which should be re-read after a gap and
// whenever the consumer cannot keep up. To avoid missing the start of a story, Subscribe first and call
// Snapshot afterwards. Events are only produced while Run is active.
func (m *Manager) Subscribe(buf int) (<-chan Event, func()) {
	s := &subscriber{ch: make(chan Event, max(buf, 1))}
	m.subMu.Lock()
	if m.subsClosed {
		close(s.ch)
		m.subMu.Unlock()
		return s.ch, func() {}
	}
	m.subs[s] = struct{}{}
	m.subMu.Unlock()
	return s.ch, func() {
		m.subMu.Lock()
		defer m.subMu.Unlock()
		if _, ok := m.subs[s]; ok {
			delete(m.subs, s)
			close(s.ch)
		}
	}
}

// flush delivers the queued events to the subscribers and to Options.OnEvent. Only the Run goroutine calls it.
func (m *Manager) flush() {
	m.mu.Lock()
	evs := m.outbox
	m.outbox = nil
	m.mu.Unlock()
	for _, e := range evs {
		m.subMu.Lock()
		for s := range m.subs {
			select {
			case s.ch <- e:
			default: // slow subscriber: drop, never block the session
			}
		}
		m.subMu.Unlock()
		if m.opts.OnEvent != nil {
			m.opts.OnEvent(e)
		}
	}
}

// Run connects to the server, registers the tunnel set and forwards traffic until ctx is cancelled (it then
// returns nil) or an unrecoverable error occurs. A Manager can be run once; a second call returns
// ErrAlreadyRunning.
//
// Connection errors are retried with exponential backoff and full jitter, forever once a session has been
// established; before that Options.MaxInitialAttempts applies (zero: no limit) and a failure that retrying cannot
// fix (unknown host, TLS certificate verification) ends Run at once, both with an *InitialConnectError. Run also
// returns the non-retryable errors of the server (unauthorized, token_expired, token_revoked, unsupported_version,
// session_replaced) as *proto.Error.
//
// A refused registration never ends Run (unless the error itself is one of those session-level codes): the
// tunnel goes to StatusFailed with the server's error, a TunnelClosed event is emitted, and the registration is
// tried again after the next reconnect. A server-sent tunnel_closed for a tunnel of the set is handled the same
// way. A session with no tunnel at all is fine: the Manager stays connected and waits for Add.
//
// When Run returns, all event subscriptions are closed and Add, Remove and Replace return ErrStopped.
func (m *Manager) Run(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return ErrAlreadyRunning
	}
	m.started, m.running = true, true
	m.mu.Unlock()

	err := m.loop(ctx)
	m.finish(err)
	return err
}

// finish marks the Manager stopped after the last event has been delivered.
func (m *Manager) finish(err error) {
	m.flush()
	m.mu.Lock()
	m.conn, m.stopped, m.running = ConnStopped, true, false
	m.retryAt = time.Time{}
	if err != nil {
		m.lastErr = err
	}
	m.mu.Unlock()
	m.subMu.Lock()
	m.subsClosed = true
	for s := range m.subs {
		close(s.ch)
	}
	clear(m.subs)
	m.subMu.Unlock()
}

func (m *Manager) setConn(c ConnState) {
	m.mu.Lock()
	m.conn = c
	m.retryAt = time.Time{}
	m.mu.Unlock()
}

// loop is the reconnect loop: it runs sessions until one ends in an error that retrying cannot fix.
func (m *Manager) loop(ctx context.Context) error {
	attempt := 0
	initialFailures := 0
	for {
		m.setConn(ConnConnecting)
		var at attemptInfo
		err := m.session(ctx, &at)
		m.flush()
		if ctx.Err() != nil {
			return nil //nolint:nilerr // cancellation is the normal way to stop; the session error is a consequence of it
		}
		if err == nil {
			err = errors.New("session ended")
		}
		if !at.connectedAt.IsZero() {
			m.everUp = true
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
		if !m.everUp {
			initialFailures++
			initialAttempt = initialFailures
			limit := m.opts.MaxInitialAttempts
			if limit > 0 && (isPermanentDialError(err) || initialFailures >= limit) {
				return &InitialConnectError{URL: m.url, Attempts: initialFailures, Err: err}
			}
		}

		if !at.connectedAt.IsZero() && time.Since(at.connectedAt) >= m.t.stableAfter {
			attempt = 0
		}
		delay := backoffDelay(attempt, m.t.backoffBase, m.t.backoffMax)
		attempt++
		delay = max(delay, min(retryAfter, m.t.maxRetryAfter))

		m.log.Info("disconnected", "err", err, "retry_in", delay)
		ev := Disconnected{Err: err, RetryIn: delay}
		if initialAttempt > 0 {
			ev.Attempt, ev.MaxAttempts = initialAttempt, max(m.opts.MaxInitialAttempts, 0)
		}
		m.mu.Lock()
		m.conn, m.retryAt, m.lastErr = ConnBackoff, time.Now().Add(delay), err
		m.postLocked(ev)
		m.mu.Unlock()
		m.flush()
		if !m.wait(ctx, delay) {
			return nil
		}
	}
}

// wait sleeps for d, delivering queued events (caused by Add, Remove, Replace) meanwhile. It returns false if ctx
// ended first.
func (m *Manager) wait(ctx context.Context, d time.Duration) bool {
	tm := time.NewTimer(d)
	defer tm.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-tm.C:
			return true
		case <-m.kick:
			m.flush()
		}
	}
}

// onConnected records a successful handshake: every tunnel starts over as pending.
func (m *Manager) onConnected(clientName string) {
	m.mu.Lock()
	m.conn, m.client, m.lastErr, m.retryAt = ConnConnected, clientName, nil, time.Time{}
	for _, rec := range m.desired {
		rec.status, rec.url, rec.err = StatusPending, "", nil
	}
	m.postLocked(Connected{ClientName: clientName})
	m.mu.Unlock()
}

// onSessionEnded drops the "ready" state of the tunnels: without a session none of them is registered. Failed
// tunnels keep their error until the next connect resets them.
func (m *Manager) onSessionEnded() {
	m.mu.Lock()
	m.conn = ConnBackoff
	for _, rec := range m.desired {
		if rec.status == StatusReady {
			rec.status, rec.url = StatusPending, ""
		}
	}
	m.mu.Unlock()
}
