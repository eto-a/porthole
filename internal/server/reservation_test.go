// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
)

// restart starts a second server on the store and port range of h, as after a restart of portholed.
func restart(t *testing.T, h *harness, mods ...func(*config.Config, *Options)) *harness {
	t.Helper()
	same := func(c *config.Config, o *Options) {
		c.TCPPortRange = itoa(h.lo) + "-" + itoa(h.hi)
		o.Store = h.st
	}
	h2 := newHarness(t, append([]func(*config.Config, *Options){same}, mods...)...)
	h2.st = h.st
	return h2
}

func TestTCPPortsSurviveRestart(t *testing.T) {
	h := newHarness(t)
	tok := h.st.newToken(t, "home")
	c := h.login(tok)

	names := []string{"ssh", "db", "web", "vnc"}
	ports := map[string]int{}
	for _, n := range names {
		ports[n] = publicPort(t, c.mustRegister(proto.KindTCP, n, 0).PublicURL)
	}

	// The first server goes away with its tunnels still registered.
	c.close()
	if err := h.srv.Close(); err != nil {
		t.Fatal(err)
	}

	h2 := restart(t, h)
	c2 := h2.login(tok)
	// Reverse order, so a random pick would not line up with the old ports by chance.
	for i := len(names) - 1; i >= 0; i-- {
		n := names[i]
		if got := publicPort(t, c2.mustRegister(proto.KindTCP, n, 0).PublicURL); got != ports[n] && portFree(ports[n]) {
			t.Errorf("tunnel %q after restart got port %d, want %d", n, got, ports[n])
		}
	}
}

// A crash leaves rows of live tunnels in the store; the next start must treat them as released.
func TestTCPPortsSurviveCrash(t *testing.T) {
	h := newHarness(t)
	tok := h.st.newToken(t, "home")
	if err := h.st.HoldPort(context.Background(), "home", "ssh", h.hi, h.clock.Now(), reservationTTL); err != nil {
		t.Fatal(err)
	}

	h2 := restart(t, h)
	c := h2.login(tok)
	if got := publicPort(t, c.mustRegister(proto.KindTCP, "ssh", 0).PublicURL); got != h.hi {
		t.Errorf("got port %d, want %d", got, h.hi)
	}
}

func TestStoredReservationRules(t *testing.T) {
	h := newHarness(t)
	tok := h.st.newToken(t, "home")
	ctx := context.Background()
	now := h.clock.Now()
	// Held for another tunnel: never handed out to "ssh". Out of range: ignored. Expired: dropped.
	if err := h.st.HoldPort(ctx, "other", "x", h.lo, now, reservationTTL); err != nil {
		t.Fatal(err)
	}
	if err := h.st.HoldPort(ctx, "home", "far", h.hi+1, now, reservationTTL); err != nil {
		t.Fatal(err)
	}
	if err := h.st.HoldPort(ctx, "home", "old", h.lo+1, now, reservationTTL); err != nil {
		t.Fatal(err)
	}
	if err := h.st.ReleasePort(ctx, "home", "old", now.Add(-reservationTTL-time.Hour)); err != nil {
		t.Fatal(err)
	}

	h2 := restart(t, h)
	if n := len(h2.srv.reserved); n != 1 {
		t.Fatalf("loaded %d reservations (%v), want 1", n, h2.srv.reserved)
	}
	c := h2.login(tok)
	for range 5 {
		if e := c.registerErr(proto.KindTCP, "ssh", h.lo); e == nil || e.Code != proto.CodePortUnavailable {
			t.Fatalf("port reserved for another tunnel: got %+v, want port_unavailable", e)
		}
	}
}

// Closing a tunnel and the client going away are both recorded, so the port is kept for its next owner.
func TestUnregisterPersistsRelease(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindTCP, "ssh", 0)
	port := publicPort(t, reg.PublicURL)

	h.st.mu.Lock()
	live := h.st.live["home/ssh"]
	h.st.mu.Unlock()
	if !live {
		t.Fatal("tunnel was not recorded in the store")
	}
	if err := c.write(&proto.Unregister{TunnelID: reg.TunnelID}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "release recorded", func() bool {
		h.st.mu.Lock()
		defer h.st.mu.Unlock()
		r := h.st.ports["home/ssh"]
		return r != nil && r.Port == port && !h.st.live["home/ssh"]
	})
}

// portFree reports whether port can be bound now. Between the two servers another program may still take a
// released port; the server then rightly picks a different one.
func portFree(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
