// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eto-a/porthole/internal/metrics"
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

		if !t.acquire() {
			c.log.Warn("tcp tunnel at its connection limit, dropping connection", "tunnel", t.id, "limit", cap(t.sem))
			c.srv.metrics.ConnOutcome(metrics.KindTCP, metrics.OutcomeLimit)
			_ = conn.Close()
			continue
		}
		c.wg.Go(func() {
			defer t.release()
			t.handleConn(conn)
		})
	}
}

// handleConn opens a stream for one visitor connection and copies bytes both ways until both directions end.
func (t *tunnel) handleConn(conn net.Conn) {
	c := t.sess
	remote := conn.RemoteAddr().String()
	stream, err := t.openStream(remote)
	if err != nil {
		c.log.Debug("open stream for tcp visitor failed", "tunnel", t.id, "remote", remote, "err", err)
		c.srv.metrics.ConnOutcome(metrics.KindTCP, metrics.OutcomeStreamError)
		_ = conn.Close()
		return
	}
	// Closing the tunnel (unregister, session end) must tear down in-flight connections too.
	stop := context.AfterFunc(t.ctx, func() {
		_ = conn.Close()
		_ = stream.Close()
	})
	defer stop()
	c.srv.metrics.ConnOutcome(metrics.KindTCP, metrics.OutcomeAccepted)
	fromVisitor, fromTunnel := pipe(conn, stream)
	c.srv.metrics.AddBytes(metrics.KindTCP, fromVisitor, fromTunnel)
}

// pipe copies a<->b. A clean EOF in one direction half-closes the other side so request/response protocols that
// shut down their write side still receive the answer; any error closes both sides. Both are closed on return.
// It returns the number of bytes read from a and from b.
func pipe(a, b net.Conn) (fromA, fromB int64) {
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		if src == a {
			fromA = n
		} else {
			fromB = n
		}
		if err != nil {
			_ = a.Close()
			_ = b.Close()
			return
		}
		halfClose(dst)
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	return fromA, fromB
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
