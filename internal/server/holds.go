// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"time"

	"github.com/eto-a/porthole/internal/proto"
)

// hold keeps a public address (HTTP label, SSH gateway address) for the (client, tunnel) pair that had it, for
// offlineGrace after its client went away. Without it a different client could register a name that composes to
// the same address (the label is "<tunnel>-<client>" and both parts may contain hyphens: client "x-b" with tunnel
// "a" and client "b" with tunnel "a-x" both give "a-x-b") and receive the visitors, cookies and SSH logins of the
// owner during a reconnect. An explicit unregister does not leave a hold.
type hold struct {
	owner string // reservationKey(client, tunnel)
	until time.Time
}

// addrKey names an address in Server.held and the like: "http:<label>" or "ssh:<address>".
func addrKey(kind, addr string) string { return kind + ":" + addr }

// sshLabel is the gateway address of the ssh tunnel name of client: "<tunnel>-<client>".
func sshLabel(client, name string) string { return name + "-" + client }

// sshAddrs returns the gateway addresses of an ssh tunnel: its label and, for the tunnel named "ssh", the bare
// client name.
func sshAddrs(client, name string) []string {
	if name == defaultSSHTunnelName {
		return []string{sshLabel(client, name), client}
	}
	return []string{sshLabel(client, name)}
}

// holdLocked reserves key for owner until now+offlineGrace.
func (s *Server) holdLocked(key, owner string, now time.Time) {
	s.held[key] = hold{owner: owner, until: now.Add(offlineGrace)}
}

// heldByOtherLocked reports whether key is reserved for an owner other than owner. Expired holds are dropped.
func (s *Server) heldByOtherLocked(key, owner string, now time.Time) bool {
	h, ok := s.held[key]
	if !ok {
		return false
	}
	if !now.Before(h.until) {
		delete(s.held, key)
		return false
	}
	return h.owner != owner
}

func (s *Server) sweepHeldLocked(now time.Time) {
	for k, h := range s.held {
		if !now.Before(h.until) {
			delete(s.held, k)
		}
	}
}

// conflictingSSHLocked reports whether registering the ssh tunnel name of client would collide with an address
// that belongs to somebody else: a live tunnel's label, a hold of another owner, or the bare name of another
// client's "ssh" tunnel (which the gateway resolves first).
func (s *Server) conflictingSSHLocked(client, name string, now time.Time) bool {
	owner := reservationKey(client, name)
	label := sshLabel(client, name)
	if t := s.sshLabels[label]; t != nil && t.sess.name != client {
		return true
	}
	if s.heldByOtherLocked(addrKey(proto.KindSSH, label), owner, now) {
		return true
	}
	if other := s.sessions[label]; other != nil && other.name != client && !other.dead {
		if _, ok := other.names[proto.KindSSH+":"+defaultSSHTunnelName]; ok {
			return true
		}
	}
	return false
}

// lookupSSH resolves the target host of a gateway direct-tcpip request to an ssh tunnel (ADR 0003): first the bare
// name of a client that has an ssh tunnel named "ssh", then the exact label "<tunnel>-<client>" of a registered ssh
// tunnel. A trailing ".<domain>" and letter case are ignored. There is no guessing where the tunnel name ends and
// the client name begins: registration keeps labels unique (see conflictingSSHLocked). Callers must answer "not
// found" and "not allowed" identically so that names cannot be enumerated.
func (s *Server) lookupSSH(target string) (*tunnel, bool) {
	target = strings.TrimSuffix(strings.ToLower(target), ".")
	target = strings.TrimSuffix(target, "."+s.domain)
	if target == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.sessions[target]; c != nil && !c.dead {
		if t := c.names[proto.KindSSH+":"+defaultSSHTunnelName]; t != nil {
			return t, true
		}
	}
	if t := s.sshLabels[target]; t != nil && !t.sess.dead {
		return t, true
	}
	return nil, false
}
