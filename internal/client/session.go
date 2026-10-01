// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/transport"
)

// errNoTunnels is returned when a session ended up without any registered tunnel.
var errNoTunnels = errors.New("no tunnel could be registered")

// errAllTunnelsClosed is returned when the server dropped every tunnel of the session.
var errAllTunnelsClosed = errors.New("server closed all tunnels")

// attemptInfo carries facts about one connection attempt back to the reconnect loop.
type attemptInfo struct {
	connectedAt time.Time // zero if the handshake never completed
}

// ctlConn serialises writes to the control stream.
type ctlConn struct {
	c       net.Conn
	timeout time.Duration
	mu      sync.Mutex
}

func (c *ctlConn) send(m proto.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.c.SetWriteDeadline(time.Now().Add(c.timeout))
	return proto.WriteMessage(c.c, m)
}

// tunnelEntry is what the client knows about a registered tunnel.
type tunnelEntry struct {
	name  string
	local string
}

// tunnelTable maps server-assigned tunnel ids to local targets.
type tunnelTable struct {
	mu sync.RWMutex
	m  map[string]tunnelEntry
}

func newTunnelTable() *tunnelTable { return &tunnelTable{m: make(map[string]tunnelEntry)} }

func (t *tunnelTable) add(id string, e tunnelEntry) {
	t.mu.Lock()
	t.m[id] = e
	t.mu.Unlock()
}

func (t *tunnelTable) lookup(id string) (tunnelEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.m[id]
	return e, ok
}

func (t *tunnelTable) remove(id string) (tunnelEntry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[id]
	delete(t.m, id)
	return e, ok
}

func (t *tunnelTable) len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.m)
}

// CheckResult describes the server as seen by a successful handshake.
type CheckResult struct {
	ClientName    string
	ServerVersion string
}

// Check dials the server and performs the handshake only, then disconnects. It uses Options.ServerURL, Token,
// Version, Logger and TLSConfig; Tunnels are ignored.
func Check(ctx context.Context, opts Options) (CheckResult, error) {
	opts.Tunnels = nil
	m, err := newManager(opts, defaultTuning(), false)
	if err != nil {
		return CheckResult{}, err
	}
	sess, _, ok, err := m.handshake(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	_ = sess.Close()
	return CheckResult{ClientName: ok.ClientName, ServerVersion: ok.ServerVersion}, nil
}

// handshake dials the server, opens the control stream and exchanges hello/hello_ok. The returned session is
// closed automatically when ctx ends; on error it is closed before returning.
func (m *Manager) handshake(ctx context.Context) (transport.Session, net.Conn, *proto.HelloOK, error) {
	dctx, cancel := context.WithTimeout(ctx, m.t.dialTimeout)
	defer cancel()
	m.log.Debug("dialing", "url", m.url)
	sess, err := transport.DialWebSocket(dctx, m.url, transport.DialOptions{TLSConfig: m.opts.TLSConfig})
	if err != nil {
		return nil, nil, nil, err
	}
	context.AfterFunc(ctx, func() { _ = sess.Close() })

	ok, ctl, err := m.hello(sess)
	if err != nil {
		_ = sess.Close()
		return nil, nil, nil, fmt.Errorf("handshake: %w", err)
	}
	return sess, ctl, ok, nil
}

func (m *Manager) hello(sess transport.Session) (*proto.HelloOK, net.Conn, error) {
	ctl, err := sess.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("open control stream: %w", err)
	}
	_ = ctl.SetDeadline(time.Now().Add(m.t.handshakeTimeout))
	err = proto.WriteMessage(ctl, &proto.Hello{
		ProtocolVersion: proto.Version,
		Token:           m.opts.Token,
		ClientVersion:   m.opts.Version,
		OS:              runtime.GOOS + "/" + runtime.GOARCH,
	})
	if err != nil {
		return nil, nil, err
	}
	ok, err := proto.ReadAs[*proto.HelloOK](ctl)
	if err != nil {
		return nil, nil, err
	}
	_ = ctl.SetDeadline(time.Time{})
	return ok, ctl, nil
}

// session runs one connection from dial to teardown. It returns a non-nil error whenever ctx is still alive.
func (m *Manager) session(ctx context.Context, at *attemptInfo) error {
	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	sess, ctlStream, hok, err := m.handshake(cctx)
	if err != nil {
		cancel()
		return err
	}
	defer func() {
		cancel()
		_ = sess.Close()
		wg.Wait()
		m.onSessionEnded()
	}()

	at.connectedAt = time.Now()
	m.log.Info("connected", "client", hok.ClientName, "server_version", hok.ServerVersion, "session", hok.SessionID)
	m.onConnected(hok.ClientName)
	m.flush()

	hbInterval := time.Duration(hok.HeartbeatIntervalMS) * time.Millisecond
	if hbInterval <= 0 {
		hbInterval = proto.DefaultHBMilli * time.Millisecond
	}
	hbTimeout := hbInterval * time.Duration(m.t.heartbeatMisses)

	ctl := &ctlConn{c: ctlStream, timeout: m.t.writeTimeout}
	msgs := make(chan proto.Message, 16)
	var readErr error
	wg.Go(func() { m.readControl(cctx, ctlStream, msgs, &readErr) })

	w := newWire(m, ctl)
	wg.Go(func() { m.acceptLoop(cctx, sess, w.table, &wg) })

	hb := time.NewTimer(hbTimeout)
	defer hb.Stop()
	regTimer := time.NewTimer(m.t.registerTimeout)
	regTimer.Stop()
	defer regTimer.Stop()
	var regC <-chan time.Time // non-nil while registrations are in flight
	settled := false          // strict mode: every registration of this session has been answered

	if err := w.reconcile(); err != nil {
		return err
	}
	for {
		// Arm the registration timer when a first request goes out, disarm it when the last reply is in.
		switch {
		case len(w.byReq) == 0:
			regTimer.Stop()
			regC = nil
		case regC == nil:
			regTimer.Reset(m.t.registerTimeout)
			regC = regTimer.C
		}
		m.flush()

		select {
		case <-cctx.Done():
			return cctx.Err()
		case <-regC:
			return fmt.Errorf("timed out waiting for %d tunnel registration(s)", len(w.byReq))
		case <-hb.C:
			return fmt.Errorf("no ping from server for %s", hbTimeout)
		case <-m.kick:
			if err := w.reconcile(); err != nil {
				return err
			}
		case msg, ok := <-msgs:
			if !ok {
				return fmt.Errorf("control stream closed: %w", readErr)
			}
			switch msg := msg.(type) {
			case *proto.Ping:
				if err := ctl.send(&proto.Pong{Seq: msg.Seq}); err != nil {
					return fmt.Errorf("send pong: %w", err)
				}
				hb.Reset(hbTimeout)
			case *proto.Registered:
				if err := w.onRegistered(msg); err != nil {
					return err
				}
			case *proto.Error:
				handled, err := w.onError(msg)
				if err != nil {
					return err
				}
				if handled {
					break
				}
				if msg.Fatal || !msg.Retryable() {
					return fmt.Errorf("server error: %w", msg)
				}
				m.log.Warn("server error", "err", msg)
			case *proto.TunnelClosed:
				w.onTunnelClosed(msg)
				if m.strict && settled && w.table.len() == 0 {
					return errAllTunnelsClosed
				}
			default:
				m.log.Debug("ignoring control message", "type", msg.MsgType())
			}
		}

		if m.strict && !settled && len(w.byReq) == 0 {
			settled = true
			m.regDone = true
			if w.table.len() == 0 {
				return errNoTunnels
			}
		}
	}
}

// wireTunnel is the session-side view of one tunnel: a registration in flight or a registered tunnel.
type wireTunnel struct {
	rec   *tunnelRec // the desired record this registration was made for
	spec  TunnelSpec
	reqID int
	id    string // server-assigned, empty while the registration is in flight
	// stale marks an in-flight registration whose record was removed or replaced meanwhile. When its reply arrives
	// the tunnel is unregistered again.
	stale bool
}

// wire is the part of a session that follows the desired tunnel set. It is only used by the goroutine running
// session, so it needs no locking; Manager.mu guards the desired set and the per-tunnel status it publishes.
type wire struct {
	m      *Manager
	ctl    *ctlConn
	table  *tunnelTable
	byName map[string]*wireTunnel
	byReq  map[int]*wireTunnel
}

func newWire(m *Manager, ctl *ctlConn) *wire {
	return &wire{
		m: m, ctl: ctl, table: newTunnelTable(),
		byName: make(map[string]*wireTunnel),
		byReq:  make(map[int]*wireTunnel),
	}
}

// reconcile brings the server in line with the desired set: tunnels that are registered or in flight but no longer
// desired are unregistered (in-flight ones as soon as their reply arrives), and pending tunnels without a
// registration are registered, in the order they were added. A name whose old registration is still in flight is
// skipped until that reply has been handled, which calls reconcile again.
func (w *wire) reconcile() error {
	m := w.m
	var unregister []string
	var register []*wireTunnel

	m.mu.Lock()
	for _, name := range slices.Sorted(maps.Keys(w.byName)) {
		wt := w.byName[name]
		if m.desired[name] == wt.rec {
			continue
		}
		if wt.id == "" {
			wt.stale = true
			continue
		}
		unregister = append(unregister, wt.id)
		w.table.remove(wt.id) // new streams for it are rejected from now on; running ones finish
		delete(w.byName, name)
	}
	var todo []*tunnelRec
	for name, rec := range m.desired {
		if _, busy := w.byName[name]; !busy && rec.status == StatusPending {
			todo = append(todo, rec)
		}
	}
	slices.SortFunc(todo, func(a, b *tunnelRec) int { return a.seq - b.seq })
	for _, rec := range todo {
		m.reqID++
		wt := &wireTunnel{rec: rec, spec: rec.spec, reqID: m.reqID}
		w.byName[rec.spec.Name] = wt
		w.byReq[wt.reqID] = wt
		register = append(register, wt)
	}
	m.mu.Unlock()

	for _, id := range unregister {
		m.log.Info("unregistering tunnel", "tunnel_id", id)
		if err := w.ctl.send(&proto.Unregister{TunnelID: id}); err != nil {
			return fmt.Errorf("unregister: %w", err)
		}
	}
	for _, wt := range register {
		sp := wt.spec
		err := w.ctl.send(&proto.Register{ReqID: wt.reqID, Kind: sp.Kind, Name: sp.Name, RemotePort: sp.RemotePort})
		if err != nil {
			return fmt.Errorf("register %q: %w", sp.Name, err)
		}
	}
	return nil
}

// forget drops the wire entry wt if it is still the one registered under its name.
func (w *wire) forget(wt *wireTunnel) {
	if w.byName[wt.spec.Name] == wt {
		delete(w.byName, wt.spec.Name)
	}
}

func (w *wire) onRegistered(msg *proto.Registered) error {
	m := w.m
	wt, found := w.byReq[msg.ReqID]
	if !found {
		m.log.Warn("registered reply for unknown request", "req_id", msg.ReqID)
		return nil
	}
	delete(w.byReq, msg.ReqID)
	if msg.TunnelID == "" {
		return errors.New("server returned a tunnel without an id")
	}
	// The record may have been removed or replaced after the request went out without reconcile having noticed yet
	// (Remove and the reply race), so the desired set is consulted here, in the same critical section that
	// publishes the new state.
	m.mu.Lock()
	current := m.desired[wt.spec.Name] == wt.rec
	if current && !wt.stale {
		wt.rec.status, wt.rec.url, wt.rec.err = StatusReady, msg.PublicURL, nil
		m.postLocked(TunnelReady{Spec: wt.spec, Name: msg.Name, PublicURL: msg.PublicURL})
	}
	m.mu.Unlock()
	if !current || wt.stale {
		w.forget(wt)
		m.log.Info("unregistering a tunnel that changed while it was being registered", "name", wt.spec.Name)
		if err := w.ctl.send(&proto.Unregister{TunnelID: msg.TunnelID}); err != nil {
			return fmt.Errorf("unregister: %w", err)
		}
		return w.reconcile()
	}
	wt.id = msg.TunnelID
	w.table.add(msg.TunnelID, tunnelEntry{name: wt.spec.Name, local: wt.spec.LocalAddr})
	m.log.Info("tunnel ready", "name", msg.Name, "url", msg.PublicURL, "local", wt.spec.LocalAddr)
	return nil
}

// onError handles an error message that answers a registration. handled is false if it does not (the caller then
// treats it as a session-level error). A non-nil error ends the session.
func (w *wire) onError(e *proto.Error) (handled bool, err error) {
	m := w.m
	wt, found := w.byReq[e.ReqID]
	if !found || e.ReqID == 0 {
		return false, nil
	}
	delete(w.byReq, e.ReqID)
	w.forget(wt)
	sp := wt.spec
	m.log.Warn("registration refused", "name", sp.Name, "code", e.Code, "message", e.Message)
	werr := fmt.Errorf("register tunnel %q: %w", sp.Name, e)
	if !e.Retryable() {
		return true, werr // token problems and the like: the whole session is lost
	}
	if m.strict && !m.regDone {
		switch e.Code {
		case proto.CodeInternal, proto.CodeShuttingDown:
			return true, werr // transient: reconnect
		}
		return true, &permanentError{err: werr}
	}
	m.mu.Lock()
	if m.desired[sp.Name] == wt.rec && !wt.stale { // otherwise nobody wants this tunnel any more
		wt.rec.status, wt.rec.url, wt.rec.err = StatusFailed, "", werr
		m.postLocked(TunnelClosed{Name: sp.Name, Reason: e.Error()})
	}
	m.mu.Unlock()
	return true, w.reconcile() // the name is free again: a replacement may be waiting for it
}

func (w *wire) onTunnelClosed(msg *proto.TunnelClosed) {
	m := w.m
	e, found := w.table.remove(msg.TunnelID)
	if !found {
		m.log.Warn("tunnel_closed for unknown tunnel", "tunnel_id", msg.TunnelID)
		return
	}
	m.log.Info("tunnel closed by server", "name", e.name, "reason", msg.Reason)
	wt := w.byName[e.name]
	if wt == nil || wt.id != msg.TunnelID {
		return
	}
	w.forget(wt)
	m.mu.Lock()
	if m.desired[e.name] == wt.rec {
		wt.rec.status, wt.rec.url = StatusFailed, ""
		wt.rec.err = fmt.Errorf("closed by the server: %s", msg.Reason)
		m.postLocked(TunnelClosed{Name: e.name, Reason: msg.Reason})
	}
	m.mu.Unlock()
}

// readControl reads the control stream until it fails. It closes out when it stops; the reason is stored in *res
// (valid after out is closed).
func (m *Manager) readControl(ctx context.Context, c net.Conn, out chan<- proto.Message, res *error) {
	defer close(out)
	for {
		msg, err := proto.ReadMessage(c)
		if err != nil {
			if errors.Is(err, proto.ErrUnknownType) {
				m.log.Warn("ignoring unknown control message", "err", err)
				continue
			}
			*res = err
			return
		}
		select {
		case out <- msg:
		case <-ctx.Done():
			*res = ctx.Err()
			return
		}
	}
}
