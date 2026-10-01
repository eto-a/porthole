// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/transport"
)

// acceptLoop accepts data streams opened by the server until the session ends. Each stream is served in its own
// goroutine, tracked by wg; at most maxStreams are served at once, extra streams are closed immediately.
func (m *Manager) acceptLoop(ctx context.Context, sess transport.Session, table *tunnelTable, wg *sync.WaitGroup) {
	sem := make(chan struct{}, m.t.maxStreams)
	for {
		c, err := sess.Accept()
		if err != nil {
			if ctx.Err() == nil {
				m.log.Debug("accept loop stopped", "err", err)
			}
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			m.log.Warn("too many concurrent streams, rejecting one", "limit", m.t.maxStreams)
			_ = c.Close()
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			m.handleStream(ctx, c, table)
		})
	}
}

// handleStream serves one data stream: read the header, dial the local target, copy both ways.
func (m *Manager) handleStream(ctx context.Context, c net.Conn, table *tunnelTable) {
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(m.t.headerTimeout))
	hdr, err := proto.ReadAs[*proto.StreamHeader](c)
	if err != nil {
		m.log.Warn("bad stream header", "err", err)
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	e, ok := table.lookup(hdr.TunnelID)
	if !ok {
		m.log.Warn("stream for unknown tunnel", "tunnel_id", hdr.TunnelID)
		return
	}

	d := net.Dialer{Timeout: m.t.localDialTimeout}
	local, err := d.DialContext(ctx, "tcp", e.local)
	if err != nil {
		m.log.Warn("cannot reach local target", "tunnel", e.name, "local", e.local, "err", err)
		return
	}
	defer local.Close()

	m.log.Debug("stream open", "tunnel", e.name, "visitor", hdr.RemoteAddr)
	pipe(ctx, c, local)
	m.log.Debug("stream closed", "tunnel", e.name, "visitor", hdr.RemoteAddr)
}

// pipe copies between stream and local in both directions with half-close semantics: when one side reaches EOF
// the write half of the other side is closed, and the other direction keeps flowing. A copy error tears down both
// sides. pipe returns when both directions are finished; cancelling ctx closes both connections.
func pipe(ctx context.Context, stream, local net.Conn) {
	stop := context.AfterFunc(ctx, func() {
		_ = stream.Close()
		_ = local.Close()
	})
	defer stop()

	var wg sync.WaitGroup
	wg.Go(func() { copyHalf(local, stream) })
	wg.Go(func() { copyHalf(stream, local) })
	wg.Wait()
}

func copyHalf(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = src.Close()
		return
	}
	closeWrite(dst)
}

// closeWrite closes the write half of c: TCP connections via CloseWrite, yamux streams via Close, which only
// closes their write half.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
