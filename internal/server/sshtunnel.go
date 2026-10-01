// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net"
	"strings"

	"github.com/eto-a/porthole/internal/proto"
)

// defaultSSHTunnelName is the name of an ssh tunnel registered without one.
const defaultSSHTunnelName = "ssh"

// lookupSSH resolves the target host of a gateway direct-tcpip request to an ssh tunnel (ADR 0003): "<client>"
// is the tunnel named "ssh" of that client, "<tunnel>-<client>" the named ssh tunnel of that client. A trailing
// ".<domain>" and letter case are ignored. Because names may contain hyphens, the whole target is tried as a
// client first, then every hyphen as the tunnel/client split, from the left. Callers must answer "not found" and
// "not allowed" identically so that names cannot be enumerated.
func (s *Server) lookupSSH(target string) (*tunnel, bool) {
	target = strings.TrimSuffix(strings.ToLower(target), ".")
	target = strings.TrimSuffix(target, "."+s.domain)
	if target == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	find := func(client, name string) *tunnel {
		c := s.sessions[client]
		if c == nil || c.dead {
			return nil
		}
		return c.names[proto.KindSSH+":"+name]
	}
	if t := find(target, defaultSSHTunnelName); t != nil {
		return t, true
	}
	for i := 0; i < len(target); i++ {
		if target[i] != '-' {
			continue
		}
		if t := find(target[i+1:], target[:i]); t != nil {
			return t, true
		}
	}
	return nil, false
}

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
