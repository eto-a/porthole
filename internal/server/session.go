// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/transport"
)

// dummyHash is compared against when a token id is unknown, so that "no such id" and "wrong secret" cost the
// same and reveal nothing through timing.
var dummyHash = auth.HashSecret("porthole-dummy-secret")

// lingerTimeout bounds how long the server keeps reading after its final error frame. Closing a socket while the
// peer is still sending makes the kernel answer with RST, and the peer then drops our unread error frame and sees a
// bare EOF instead of, say, token_revoked. So after the last frame we half-close and drain until the peer closes.
const lingerTimeout = 2 * time.Second

// session is one connected client. Its tunnel maps are guarded by Server.mu.
type session struct {
	srv     *Server
	id      string
	tokenID string

	remote        string // peer address, for the admin API
	since         time.Time
	clientVersion string
	os            string
	name          string // client name = token name
	ts            transport.Session
	ctrl          net.Conn
	log           *slog.Logger

	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup // goroutines of this session
	ctrlDone chan struct{}  // closed when controlLoop returns

	wmu sync.Mutex // serialises writes to ctrl

	sent  atomic.Uint64 // last ping seq sent
	acked atomic.Uint64 // highest pong seq received

	killOnce sync.Once
	reason   string       // why the session ended, for logs; written before cancel
	farewell *proto.Error // sent on the control stream during teardown; written before cancel

	// guarded by Server.mu
	dead    bool
	tunnels map[string]*tunnel // by tunnel id
	names   map[string]*tunnel // by kind+":"+name
}

// runSession drives one accepted transport session from handshake to teardown.
func (s *Server) runSession(ts transport.Session, ip string) {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	sess, err := s.handshake(ctx, cancel, ts, ip)
	if err != nil {
		_ = ts.Close()
		return
	}
	sess.run()
}

// handshake performs session establishment (protocol.md §1). On failure the peer has already been told why.
func (s *Server) handshake(ctx context.Context, cancel context.CancelFunc, ts transport.Session, ip string) (*session, error) {
	// One deadline for the whole handshake, plus abort on server shutdown. Closing the transport unblocks
	// every pending read and write below.
	timer := time.AfterFunc(s.hsTimeout, func() { _ = ts.Close() })
	defer timer.Stop()
	stop := context.AfterFunc(ctx, func() { _ = ts.Close() })
	defer stop()

	ctrl, err := ts.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept control stream: %w", err)
	}

	reject := func(e *proto.Error) error {
		e.Fatal = true
		_ = writeFrame(ctrl, nil, e)
		_ = ctrl.Close() // half-close: FIN after the error frame
		_ = ctrl.SetReadDeadline(time.Now().Add(lingerTimeout))
		_, _ = io.Copy(io.Discard, io.LimitReader(ctrl, proto.MaxFrameSize))
		return e
	}

	if wait, blocked := s.limiter.blocked(ip, s.now()); blocked {
		s.log.Warn("handshake refused: too many failed attempts", "ip", ip)
		return nil, reject(&proto.Error{
			Code:         proto.CodeLimitExceeded,
			Message:      "too many failed handshakes from this address",
			RetryAfterMS: int(wait / time.Millisecond),
		})
	}

	hello, err := proto.ReadAs[*proto.Hello](ctrl)
	if err != nil {
		return nil, reject(&proto.Error{Code: proto.CodeInvalidRequest, Message: "expected hello"})
	}
	if hello.ProtocolVersion < proto.MinVersion || hello.ProtocolVersion > proto.Version {
		return nil, reject(&proto.Error{
			Code:    proto.CodeUnsupportedVersion,
			Message: fmt.Sprintf("supported protocol versions: %d..%d", proto.MinVersion, proto.Version),
		})
	}

	tok, perr, fromClient := s.authenticate(ctx, hello.Token)
	if perr != nil {
		if fromClient {
			s.limiter.fail(ip, s.now())
			s.log.Warn("handshake failed", "ip", ip, "code", perr.Code)
		}
		return nil, reject(perr)
	}

	touchCtx, touchCancel := context.WithTimeout(ctx, storeTimeout)
	if err := s.store.TouchToken(touchCtx, tok.ID, s.now()); err != nil {
		s.log.Warn("touch token failed", "token_id", tok.ID, "err", err)
	}
	touchCancel()

	id := randHex(8)
	sess := &session{
		srv:     s,
		id:      id,
		tokenID: tok.ID,
		name:    tok.Name,

		remote:        ts.RemoteAddr().String(),
		since:         s.now(),
		clientVersion: hello.ClientVersion,
		os:            hello.OS,
		ts:            ts,
		ctrl:          ctrl,
		log:           s.log.With("client", tok.Name, "session", id, "token_id", tok.ID),
		ctx:           ctx,
		cancel:        cancel,
		ctrlDone:      make(chan struct{}),
		tunnels:       make(map[string]*tunnel),
		names:         make(map[string]*tunnel),
	}
	if err := s.adopt(sess); err != nil {
		return nil, reject(&proto.Error{Code: proto.CodeShuttingDown, Message: "server is shutting down"})
	}
	ok := &proto.HelloOK{
		SessionID:           id,
		ClientName:          tok.Name,
		ServerVersion:       s.version,
		HeartbeatIntervalMS: int(s.hb / time.Millisecond),
	}
	if err := sess.send(ok); err != nil {
		s.releaseAll(sess)
		return nil, fmt.Errorf("send hello_ok: %w", err)
	}
	sess.log.Info("session started", "remote", ts.RemoteAddr().String(), "client_version", hello.ClientVersion, "os", hello.OS)
	return sess, nil
}

// authenticate checks a hello token. fromClient reports whether a failure is the client's fault (counts against
// the per-IP limiter) as opposed to a server-side problem.
func (s *Server) authenticate(ctx context.Context, raw string) (tok *store.Token, perr *proto.Error, fromClient bool) {
	unauthorized := &proto.Error{Code: proto.CodeUnauthorized, Message: "invalid token"}
	parsed, err := auth.Parse(raw)
	if err != nil {
		return nil, unauthorized, true
	}
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	tok, err = s.store.GetToken(sctx, parsed.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		auth.Verify(parsed.Secret, dummyHash)
		return nil, unauthorized, true
	case err != nil:
		s.log.Error("store lookup failed", "err", err)
		return nil, &proto.Error{Code: proto.CodeInternal, Message: "internal error"}, false
	}
	if !auth.Verify(parsed.Secret, tok.SecretHash) {
		return nil, unauthorized, true
	}
	if uerr := tok.Usable(s.now()); uerr != nil {
		return nil, usableError(uerr), false
	}
	return tok, nil, false
}

// usableError maps store.Token.Usable errors to protocol errors.
func usableError(err error) *proto.Error {
	if errors.Is(err, store.ErrExpired) {
		return &proto.Error{Code: proto.CodeTokenExpired, Message: "token expired"}
	}
	return &proto.Error{Code: proto.CodeTokenRevoked, Message: "token revoked"}
}

// recheck re-reads a token from the store. perr is set when the token may no longer be used; err when the
// store itself failed (the caller decides how to degrade).
func (s *Server) recheck(ctx context.Context, tokenID string) (tok *store.Token, perr *proto.Error, err error) {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	tok, err = s.store.GetToken(sctx, tokenID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &proto.Error{Code: proto.CodeTokenRevoked, Message: "token no longer exists"}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if uerr := tok.Usable(s.now()); uerr != nil {
		return nil, usableError(uerr), nil
	}
	return tok, nil, nil
}

// writeFrame writes one message to the control stream, serialised by mu when non-nil.
func writeFrame(c net.Conn, mu *sync.Mutex, m proto.Message) error {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
	return proto.WriteMessage(c, m)
}

// send writes a control message; safe for concurrent use.
func (c *session) send(m proto.Message) error { return writeFrame(c.ctrl, &c.wmu, m) }

func (c *session) sendError(reqID int, code, msg string) {
	if err := c.send(&proto.Error{ReqID: reqID, Code: code, Message: msg}); err != nil {
		c.kill("control write failed: "+err.Error(), nil)
	}
}

// kill ends the session: it records why, optionally a final error for the peer, and cancels the session
// context. The actual cleanup happens in run's teardown. The first call wins.
func (c *session) kill(reason string, farewell *proto.Error) {
	c.killOnce.Do(func() {
		c.reason = reason
		c.farewell = farewell
		c.cancel()
	})
}

// run starts the session goroutines and blocks until the session is over and fully cleaned up.
func (c *session) run() {
	c.wg.Go(c.controlLoop)
	c.wg.Go(c.pingLoop)
	c.wg.Go(c.revalidateLoop)
	c.wg.Go(c.rejectExtraStreams)

	<-c.ctx.Done()
	c.teardown()
}

func (c *session) teardown() {
	// If the context was cancelled from outside (server shutdown) nobody called kill. Claim the Once so that a
	// late kill cannot write reason/farewell while we read them.
	c.killOnce.Do(func() { c.reason = "context cancelled" })
	farewell := c.farewell
	reason := c.reason
	if farewell == nil && c.srv.ctx.Err() != nil {
		farewell = &proto.Error{Code: proto.CodeShuttingDown, Message: "server is shutting down", Fatal: true}
		reason = "server shutdown"
	}
	if farewell != nil {
		farewell.Fatal = true
		if c.send(farewell) == nil {
			_ = c.ctrl.Close() // half-close; controlLoop keeps draining until the peer closes (see lingerTimeout)
			t := time.NewTimer(lingerTimeout)
			select {
			case <-c.ctrlDone:
			case <-t.C:
			}
			t.Stop()
		}
	}
	c.srv.releaseAll(c)
	_ = c.ctrl.Close()
	_ = c.ts.Close()
	c.wg.Wait()
	c.log.Info("session ended", "reason", reason)
}

// controlLoop reads the control stream until the session ends (protocol.md §1: it is read continuously).
func (c *session) controlLoop() {
	defer close(c.ctrlDone)
	for {
		m, err := proto.ReadMessage(c.ctrl)
		if c.ctx.Err() != nil {
			if err != nil {
				return
			}
			continue // the session is ending: drain so the peer can read our farewell (see lingerTimeout)
		}
		if errors.Is(err, proto.ErrUnknownType) {
			c.log.Debug("ignoring unknown control message", "err", err)
			continue
		}
		if err != nil {
			if errors.Is(err, proto.ErrFrameSize) {
				c.kill("protocol error: "+err.Error(), &proto.Error{Code: proto.CodeInvalidRequest, Message: "invalid frame size"})
			} else {
				c.kill("control stream closed: "+err.Error(), nil)
			}
			return
		}
		switch m := m.(type) {
		case *proto.Pong:
			c.onPong(m.Seq)
		case *proto.Register:
			c.handleRegister(m)
		case *proto.Unregister:
			c.handleUnregister(m)
		case *proto.Error:
			c.log.Warn("client reported an error", "code", m.Code, "message", m.Message)
		default:
			c.log.Debug("ignoring unexpected control message", "type", m.MsgType())
		}
	}
}

func (c *session) onPong(seq uint64) {
	if seq > c.sent.Load() {
		return // never sent; ignore
	}
	for {
		cur := c.acked.Load()
		if seq <= cur || c.acked.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// pingLoop sends a ping every heartbeat interval and closes the session after maxMissedPongs unanswered pings.
func (c *session) pingLoop() {
	tk := time.NewTicker(c.srv.hb)
	defer tk.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-tk.C:
		}
		sent := c.sent.Load()
		if sent-c.acked.Load() >= maxMissedPongs {
			c.kill("heartbeat timeout", nil)
			return
		}
		c.sent.Store(sent + 1)
		if err := c.send(&proto.Ping{Seq: sent + 1}); err != nil {
			c.kill("ping write failed: "+err.Error(), nil)
			return
		}
	}
}

// revalidateLoop re-reads the session's token periodically so that revocation and expiry reach live sessions.
func (c *session) revalidateLoop() {
	tk := time.NewTicker(c.srv.revalidate)
	defer tk.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-tk.C:
		}
		tok, perr, err := c.srv.recheck(c.ctx, c.tokenID)
		if c.ctx.Err() != nil {
			return
		}
		if err != nil {
			c.log.Warn("token revalidation failed, keeping the session", "err", err)
			continue
		}
		if perr != nil {
			perr.Fatal = true
			c.kill("token no longer usable: "+perr.Code, perr)
			return
		}
		c.enforceScopes(tok)
	}
}

// rejectExtraStreams enforces protocol.md §1.3: after the control stream the client must not open streams.
func (c *session) rejectExtraStreams() {
	st, err := c.ts.Accept()
	if err != nil {
		return
	}
	_ = st.Close()
	c.kill("protocol error: unexpected stream", &proto.Error{
		Code:    proto.CodeInvalidRequest,
		Message: "clients must not open streams after the control stream",
	})
}

// openStream opens a data stream towards the client for tunnel tunnelID and writes the stream header.
func (c *session) openStream(ctx context.Context, tunnelID, remote string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st, err := c.ts.Open()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	_ = st.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := proto.WriteMessage(st, &proto.StreamHeader{TunnelID: tunnelID, RemoteAddr: remote}); err != nil {
		_ = st.Close()
		return nil, err
	}
	_ = st.SetWriteDeadline(time.Time{})
	return st, nil
}
