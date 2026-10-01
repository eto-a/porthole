// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/transport"
)

func TestSilentHandshakesCountAsFailures(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.HandshakeTimeout = 50 * time.Millisecond })
	good := h.st.newToken(t, "home")
	for range failBurst + 1 {
		ts, ctrl := dialSession(t, h.wsURL, transport.DialOptions{})
		_ = ctrl
		select {
		case <-ts.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("silent session not closed")
		}
		_ = ts.Close()
		time.Sleep(20 * time.Millisecond) // stay below the pending-session cap
	}
	waitFor(t, "limiter", func() bool {
		_, blocked := h.srv.limiter.blocked(surfaceHandshake, "127.0.0.1", h.clock.Now())
		return blocked
	})
	_ = wantError(t, rawHandshake(t, h.wsURL, goodHello(good.str)), proto.CodeLimitExceeded, true)
}

// A2/N-07/N-10: separate buckets per surface, IPv6 by /64, no fail-open when the table is full.
func TestLimiterSurfaces(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newFailLimiter()
	for range failBurst + 1 {
		l.fail(surfaceJoin, "203.0.113.5", now)
	}
	if _, b := l.blocked(surfaceJoin, "203.0.113.5", now); !b {
		t.Fatal("join bucket not exhausted")
	}
	for _, s := range []int{surfaceHandshake, surfaceAdmin, surfaceSSH} {
		if _, b := l.blocked(s, "203.0.113.5", now); b {
			t.Errorf("surface %d blocked by failures on join", s)
		}
	}
}

func TestLimiterIPv6Prefix(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newFailLimiter()
	for i := range failBurst + 1 {
		l.fail(surfaceHandshake, fmt.Sprintf("2001:db8:1:2:%x::1", i+1), now) // same /64, different hosts
	}
	if _, b := l.blocked(surfaceHandshake, "2001:db8:1:2:ffff::9", now); !b {
		t.Error("a /64 must share one bucket")
	}
	if _, b := l.blocked(surfaceHandshake, "2001:db8:1:3::1", now); b {
		t.Error("another /64 must not be affected")
	}
}

func TestLimiterFullTableStillLimits(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newFailLimiter()
	l.maxKeys = 64
	for i := range 64 {
		l.fail(surfaceHandshake, fmt.Sprintf("10.1.0.%d", i), now)
	}
	// A new attacker address arrives while the table is full; it must still be tracked and limited.
	for range failBurst + 1 {
		l.fail(surfaceHandshake, "198.51.100.77", now)
	}
	if _, b := l.blocked(surfaceHandshake, "198.51.100.77", now); !b {
		t.Fatal("a full table made the limiter fail open")
	}
	if n := l.size(); n > 64 {
		t.Errorf("table grew to %d entries, cap is 64", n)
	}
}
