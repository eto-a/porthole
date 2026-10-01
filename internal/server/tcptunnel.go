// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eto-a/porthole/internal/metrics"
	"github.com/eto-a/porthole/internal/traffic"
)

const (
	acceptBackoffFloor = 5 * time.Millisecond
	acceptBackoffMax   = time.Second
)

// acceptLoop turns every connection accepted on the tunnel's public port into a data stream. It runs until the
// tunnel's listener is closed.
func (t *tunnel) acceptLoop() {
	c := t.sess
	backoff := acceptBackoffFloor
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if t.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient failure (e.g. out of file descriptors): back off instead of spinning.
			c.log.Warn("tcp accept failed", "tunnel", t.id, "port", t.port, "err", err)
			select {
			case <-t.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, acceptBackoffMax)
			continue
		}
		backoff = acceptBackoffFloor

		ip := ipOf(conn.RemoteAddr().String())
		switch {
		case !c.srv.tcpConns.acquire(ip):
			c.log.Warn("tcp visitor at its per-IP connection limit, dropping connection", "tunnel", t.id, "ip", ip)
			t.refuseLimit(conn)
			continue
		case !t.acquire():
			c.srv.tcpConns.release(ip)
			c.log.Warn("tcp tunnel at its connection limit, dropping connection", "tunnel", t.id, "limit", cap(t.sem))
			t.refuseLimit(conn)
			continue
		}
		c.wg.Go(func() {
			defer t.release()
			defer c.srv.tcpConns.release(ip)
			t.handleConn(conn)
		})
	}
}

// refuseLimit drops a visitor connection that is over a limit and records it.
func (t *tunnel) refuseLimit(conn net.Conn) {
	entry := t.connEntry(traffic.KindTCP, conn.RemoteAddr().String())
	entry.Outcome = traffic.OutcomeLimit
	t.sess.srv.recordConn(entry, t.sess.srv.now())
	t.sess.srv.metrics.ConnOutcome(metrics.KindTCP, metrics.OutcomeLimit)
	_ = conn.Close()
}

// handleConn opens a stream for one visitor connection and copies bytes both ways until both directions end.
func (t *tunnel) handleConn(conn net.Conn) {
	c := t.sess
	remote := conn.RemoteAddr().String()
	s := c.srv
	start := s.now()
	entry := t.connEntry(traffic.KindTCP, remote)
	stream, err := t.openStream(remote)
	if err != nil {
		c.log.Debug("open stream for tcp visitor failed", "tunnel", t.id, "remote", remote, "err", err)
		c.srv.metrics.ConnOutcome(metrics.KindTCP, metrics.OutcomeStreamError)
		_ = conn.Close()
		entry.Outcome = traffic.OutcomeRefused
		s.recordConn(entry, start)
		return
	}
	// Closing the tunnel (unregister, session end) must tear down in-flight connections too.
	stop := context.AfterFunc(t.ctx, func() {
		_ = conn.Close()
		_ = stream.Close()
	})
	defer stop()
	c.srv.metrics.ConnOutcome(metrics.KindTCP, metrics.OutcomeAccepted)
	entry.BytesIn, entry.BytesOut = pipeIdle(conn, stream, s.tcpIdle, s.tcpHalfClose)
	c.srv.metrics.AddBytes(metrics.KindTCP, entry.BytesIn, entry.BytesOut)
	entry.Outcome = traffic.OutcomeOK
	s.recordConn(entry, start)
}

// connEntry starts the journal entry of a connection to t from the visitor address remote.
func (t *tunnel) connEntry(kind, remote string) traffic.Conn {
	return traffic.Conn{TunnelID: t.id, Tunnel: t.name, Client: t.sess.name, Kind: kind, VisitorIP: ipOf(remote)}
}

// pipe copies a<->b without an idle limit; see pipeIdle.
func pipe(a, b net.Conn) (aToB, bToA int64) { return pipeIdle(a, b, 0, 0) }

// pipeIdle copies a<->b. A clean EOF in one direction half-closes the other side so request/response protocols
// that shut down their write side still receive the answer; any error closes both sides. Both are closed on
// return. It returns the number of bytes copied from a to b and from b to a.
//
// With idle > 0 the pair is closed once no byte has moved in either direction for idle. After one direction has
// ended, the other gets at most halfClosed of silence (when halfClosed > 0): a peer that half-closed and then went
// away would otherwise hold the slot forever. The two limits are independent: idle = 0 does not lift halfClosed.
func pipeIdle(a, b net.Conn, idle, halfClosed time.Duration) (aToB, bToA int64) {
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	defer closeBoth()
	var ended atomic.Bool // one direction is done
	touch := func() {}
	if idle > 0 || halfClosed > 0 {
		timer := time.AfterFunc(time.Hour, closeBoth)
		defer timer.Stop()
		touch = func() {
			d := idle
			if ended.Load() && halfClosed > 0 && (d <= 0 || halfClosed < d) {
				d = halfClosed
			}
			if d > 0 {
				timer.Reset(d)
			} else {
				timer.Stop()
			}
		}
		touch()
	}
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		var err error
		*n, err = io.Copy(activityWriter{w: dst, touch: touch}, src)
		if err != nil {
			closeBoth()
			return
		}
		ended.Store(true)
		touch()
		halfClose(dst)
	}
	wg.Add(2)
	go cp(a, b, &bToA)
	go cp(b, a, &aToB)
	wg.Wait()
	return aToB, bToA
}

// activityWriter reports every write to touch, before and after it (a write blocked by a slow reader is activity
// of the connection, not idleness).
type activityWriter struct {
	w     io.Writer
	touch func()
}

func (a activityWriter) Write(p []byte) (int, error) {
	a.touch()
	n, err := a.w.Write(p)
	a.touch()
	return n, err
}

// halfClose shuts down the write side of c. For TCP that is CloseWrite; yamux streams implement Close as a
// half-close already (the read side stays usable until the peer closes its write side).
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
