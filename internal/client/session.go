// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
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
	r, err := newRunner(opts, defaultTuning(), false)
	if err != nil {
		return CheckResult{}, err
	}
	sess, _, ok, err := r.handshake(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	_ = sess.Close()
	return CheckResult{ClientName: ok.ClientName, ServerVersion: ok.ServerVersion}, nil
}

// handshake dials the server, opens the control stream and exchanges hello/hello_ok. The returned session is
// closed automatically when ctx ends; on error it is closed before returning.
func (r *runner) handshake(ctx context.Context) (transport.Session, net.Conn, *proto.HelloOK, error) {
	dctx, cancel := context.WithTimeout(ctx, r.t.dialTimeout)
	defer cancel()
	r.log.Debug("dialing", "url", r.url)
	sess, err := transport.DialWebSocket(dctx, r.url, transport.DialOptions{TLSConfig: r.opts.TLSConfig})
	if err != nil {
		return nil, nil, nil, err
	}
	context.AfterFunc(ctx, func() { _ = sess.Close() })

	ok, ctl, err := r.hello(sess)
	if err != nil {
		_ = sess.Close()
		return nil, nil, nil, fmt.Errorf("handshake: %w", err)
	}
	return sess, ctl, ok, nil
}

func (r *runner) hello(sess transport.Session) (*proto.HelloOK, net.Conn, error) {
	ctl, err := sess.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("open control stream: %w", err)
	}
	_ = ctl.SetDeadline(time.Now().Add(r.t.handshakeTimeout))
	err = proto.WriteMessage(ctl, &proto.Hello{
		ProtocolVersion: proto.Version,
		Token:           r.opts.Token,
		ClientVersion:   r.opts.Version,
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
func (r *runner) session(ctx context.Context, at *attemptInfo) error {
	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	sess, ctlStream, hok, err := r.handshake(cctx)
	if err != nil {
		cancel()
		return err
	}
	defer func() {
		cancel()
		_ = sess.Close()
		wg.Wait()
	}()

	at.connectedAt = time.Now()
	r.log.Info("connected", "client", hok.ClientName, "server_version", hok.ServerVersion, "session", hok.SessionID)
	r.emit(Connected{ClientName: hok.ClientName})

	hbInterval := time.Duration(hok.HeartbeatIntervalMS) * time.Millisecond
	if hbInterval <= 0 {
		hbInterval = proto.DefaultHBMilli * time.Millisecond
	}
	hbTimeout := hbInterval * time.Duration(r.t.heartbeatMisses)

	ctl := &ctlConn{c: ctlStream, timeout: r.t.writeTimeout}
	msgs := make(chan proto.Message, 16)
	var readErr error
	wg.Go(func() { r.readControl(cctx, ctlStream, msgs, &readErr) })

	table := newTunnelTable()
	pending := make(map[int]TunnelSpec, len(r.specs))
	for _, sp := range r.specs {
		r.reqID++
		pending[r.reqID] = sp
		err := ctl.send(&proto.Register{ReqID: r.reqID, Kind: sp.Kind, Name: sp.Name, RemotePort: sp.RemotePort})
		if err != nil {
			return fmt.Errorf("register %q: %w", sp.Name, err)
		}
	}

	hb := time.NewTimer(hbTimeout)
	defer hb.Stop()
	regTimer := time.NewTimer(r.t.registerTimeout)
	defer regTimer.Stop()
	regC := regTimer.C
	accepting := false

	for {
		select {
		case <-cctx.Done():
			return cctx.Err()
		case <-regC:
			return fmt.Errorf("timed out waiting for %d tunnel registration(s)", len(pending))
		case <-hb.C:
			return fmt.Errorf("no ping from server for %s", hbTimeout)
		case m, ok := <-msgs:
			if !ok {
				return fmt.Errorf("control stream closed: %w", readErr)
			}
			switch m := m.(type) {
			case *proto.Ping:
				if err := ctl.send(&proto.Pong{Seq: m.Seq}); err != nil {
					return fmt.Errorf("send pong: %w", err)
				}
				hb.Reset(hbTimeout)
			case *proto.Registered:
				sp, found := pending[m.ReqID]
				if !found {
					r.log.Warn("registered reply for unknown request", "req_id", m.ReqID)
					break
				}
				delete(pending, m.ReqID)
				if m.TunnelID == "" {
					return errors.New("server returned a tunnel without an id")
				}
				table.add(m.TunnelID, tunnelEntry{name: m.Name, local: sp.LocalAddr})
				r.log.Info("tunnel ready", "name", m.Name, "url", m.PublicURL, "local", sp.LocalAddr)
				r.emit(TunnelReady{Spec: sp, Name: m.Name, PublicURL: m.PublicURL})
			case *proto.Error:
				if sp, found := pending[m.ReqID]; found && m.ReqID != 0 {
					delete(pending, m.ReqID)
					if err := r.registrationFailed(sp, m); err != nil {
						return err
					}
					break
				}
				if m.Fatal || !m.Retryable() {
					return fmt.Errorf("server error: %w", m)
				}
				r.log.Warn("server error", "err", m)
			case *proto.TunnelClosed:
				e, found := table.remove(m.TunnelID)
				if !found {
					r.log.Warn("tunnel_closed for unknown tunnel", "tunnel_id", m.TunnelID)
					break
				}
				r.log.Info("tunnel closed by server", "name", e.name, "reason", m.Reason)
				r.emit(TunnelClosed{Name: e.name, Reason: m.Reason})
				if accepting && table.len() == 0 {
					return errAllTunnelsClosed
				}
			default:
				r.log.Debug("ignoring control message", "type", m.MsgType())
			}
		}

		if !accepting && len(pending) == 0 {
			regC = nil
			r.registered = true
			if table.len() == 0 {
				return errNoTunnels
			}
			accepting = true
			wg.Go(func() { r.acceptLoop(cctx, sess, table, &wg) })
		}
	}
}

// registrationFailed decides what a refused registration means. A nil result means "carry on without this tunnel".
func (r *runner) registrationFailed(sp TunnelSpec, e *proto.Error) error {
	r.log.Warn("registration refused", "name", sp.Name, "code", e.Code, "message", e.Message)
	if !e.Retryable() {
		return fmt.Errorf("register tunnel %q: %w", sp.Name, e)
	}
	if !r.registered {
		wrapped := fmt.Errorf("register tunnel %q: %w", sp.Name, e)
		switch e.Code {
		case proto.CodeInternal, proto.CodeShuttingDown:
			return wrapped // transient: reconnect
		}
		return &permanentError{err: wrapped}
	}
	r.emit(TunnelClosed{Name: sp.Name, Reason: e.Error()})
	return nil
}

// readControl reads the control stream until it fails. It closes out when it stops; the reason is stored in *res
// (valid after out is closed).
func (r *runner) readControl(ctx context.Context, c net.Conn, out chan<- proto.Message, res *error) {
	defer close(out)
	for {
		m, err := proto.ReadMessage(c)
		if err != nil {
			if errors.Is(err, proto.ErrUnknownType) {
				r.log.Warn("ignoring unknown control message", "err", err)
				continue
			}
			*res = err
			return
		}
		select {
		case out <- m:
		case <-ctx.Done():
			*res = ctx.Err()
			return
		}
	}
}
