// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/transport"
)

// A client that cycles through TCP names keeps at most the cap of reservations, in memory and in the store, and
// cannot starve the others of public ports.
func TestReservationsPerClientAreCapped(t *testing.T) {
	h := newHarness(t, func(c *config.Config, _ *Options) { c.MaxTunnelsPerClient = 2 })
	limit := max(minReservationsPerClient, 2*h.cfg.MaxTunnelsPerClient)
	if h.hi-h.lo+1 <= limit {
		t.Fatalf("test window of %d ports is not larger than the cap %d", h.hi-h.lo+1, limit)
	}
	a := h.login(h.st.newToken(t, "alpha"))
	for i := range h.hi - h.lo + 1 + 10 {
		reg := a.mustRegister(proto.KindTCP, "t"+strconv.Itoa(i), 0)
		if err := a.write(&proto.Unregister{TunnelID: reg.TunnelID}); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "unregister", func() bool { return h.srv.tunnelCount() == 0 })
	}

	h.srv.mu.Lock()
	n := 0
	for _, r := range h.srv.reserved {
		if r.client == "alpha" {
			n++
		}
	}
	h.srv.mu.Unlock()
	if n != limit {
		t.Errorf("alpha holds %d reservations, want %d", n, limit)
	}

	b := h.login(h.st.newToken(t, "beta"))
	if e, ok := b.register(proto.KindTCP, "db", 0).(*proto.Error); ok {
		t.Fatalf("another client got %+v, want a port", e)
	}

	// The evicted ones are expired in the store as well, so a restart does not bring them back.
	waitFor(t, "store trimmed", func() bool {
		rs, err := h.st.LoadPortReservations(context.Background(), h.clock.Now(), reservationTTL)
		if err != nil {
			t.Fatal(err)
		}
		cnt := 0
		for _, r := range rs {
			if r.Client == "alpha" {
				cnt++
			}
		}
		return cnt == limit
	})
}

// The handshake deadline must not fire after the session was adopted: a handshake that timed out while the store
// was slow does not replace the live session of the same client.
func TestTimedOutHandshakeDoesNotReplaceLiveSession(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.HandshakeTimeout = 300 * time.Millisecond })
	tok := h.st.newToken(t, "home")
	old := h.login(tok)

	h.st.touchDelay.Store(int64(700 * time.Millisecond))
	ts, ctrl := dialSession(t, h.wsURL, transport.DialOptions{})
	defer ts.Close()
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
	if err := proto.WriteMessage(ctrl, goodHello(tok.str)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ts.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server did not drop the handshake that ran past its deadline")
	}
	// The deadline closed the transport while the store call is still running; let the handshake run to its end.
	time.Sleep(800 * time.Millisecond)
	h.st.touchDelay.Store(0)

	old.mustRegister(proto.KindHTTP, "web", 0) // the old session is still the live one
	if n := h.srv.sessionCount(); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}
}
