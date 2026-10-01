// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"net"
	"sync/atomic"
)

// ErrPreAuthBudget is the read error of a connection whose peer sent more than its pre-authentication byte budget.
var ErrPreAuthBudget = errors.New("transport: peer sent too much data before authenticating")

// budgetConn limits how many bytes the peer may send before the owner calls lift. yamux buffers the data of
// streams nobody has accepted yet (up to 256 KiB per stream, the initial window is not configurable), so without a
// byte budget an unauthenticated peer could make the server hold tens of megabytes per connection. The legitimate
// pre-authentication traffic is one yamux SYN and one hello frame (at most proto.MaxFrameSize).
type budgetConn struct {
	net.Conn
	left   atomic.Int64
	lifted atomic.Bool
}

func (c *budgetConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.lifted.Load() && c.left.Add(-int64(n)) < 0 {
		_ = c.Close()
		return 0, ErrPreAuthBudget
	}
	return n, err
}

func (c *budgetConn) lift() { c.lifted.Store(true) }

// Gated is implemented by the sessions that AcceptWebSocketGated returns.
type Gated interface {
	Session
	// Release lifts the pre-authentication byte budget; call it once the peer has authenticated.
	Release()
}

func (y *yamuxSession) Release() {
	if y.gate != nil {
		y.gate.lift()
	}
}
