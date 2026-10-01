// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net"
)

// defaultSSHTunnelName is the name of an ssh tunnel registered without one.
const defaultSSHTunnelName = "ssh"

// acquire reserves one concurrent-connection slot of t and reports false when the tunnel is at its limit.
// Every successful acquire must be paired with release.
func (t *tunnel) acquire() bool {
	select {
	case t.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (t *tunnel) release() { <-t.sem }

// openStream opens a data stream to the tunnel's client, exactly as a TCP tunnel does for an accepted
// connection. remote is the visitor address shown to the client. The caller closes the stream; it is also torn
// down when the tunnel goes away (t.ctx).
func (t *tunnel) openStream(remote string) (net.Conn, error) {
	return t.sess.openStream(t.ctx, t.id, remote)
}
