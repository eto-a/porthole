// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

// goOffline disconnects c and moves the clock past the offline grace, so that nothing but a permanent claim can
// keep its names.
func goOffline(t *testing.T, h *harness, c *client) {
	t.Helper()
	c.close()
	waitFor(t, "session gone", func() bool { return h.srv.sessionCount() == 0 })
	h.clock.advance(2 * offlineGrace)
}

func wantNameTaken(t *testing.T, e *proto.Error) {
	t.Helper()
	if e.Code != proto.CodeNameTaken || !strings.Contains(e.Message, "reserved") {
		t.Fatalf("got %+v, want name_taken that says the name is reserved", e)
	}
}

// Client "home" with tunnel "web-a" and client "a-home" with tunnel "web" both compose the label "web-a-home".
// The first one to register keeps it for good, in either order, after the grace period and after a restart.
func TestLabelClaimHTTPFirstPairKeepsIt(t *testing.T) {
	type pair struct{ client, tunnel string }
	home, ahome := pair{"home", "web-a"}, pair{"a-home", "web"}
	for _, order := range [][2]pair{{home, ahome}, {ahome, home}} {
		first, second := order[0], order[1]
		t.Run(first.client+"_first", func(t *testing.T) {
			h := newHarness(t)
			tok1 := h.st.newToken(t, first.client)
			tok2 := h.st.newToken(t, second.client)

			c1 := h.login(tok1)
			reg := c1.mustRegister(proto.KindHTTP, first.tunnel, 0)
			if !strings.HasPrefix(reg.PublicURL, "https://web-a-home.") {
				t.Fatalf("public url %q", reg.PublicURL)
			}
			goOffline(t, h, c1)

			c2 := h.login(tok2)
			wantNameTaken(t, c2.registerErr(proto.KindHTTP, second.tunnel, 0))
			c2.close()
			waitFor(t, "session gone", func() bool { return h.srv.sessionCount() == 0 })

			// The owner comes back and gets its label.
			c1 = h.login(tok1)
			c1.mustRegister(proto.KindHTTP, first.tunnel, 0)
			goOffline(t, h, c1)

			// A restart forgets every in-memory hold; the claim is in the store.
			if err := h.srv.Close(); err != nil {
				t.Fatal(err)
			}
			h2 := restart(t, h)
			c2 = h2.login(tok2)
			wantNameTaken(t, c2.registerErr(proto.KindHTTP, second.tunnel, 0))
			c1 = h2.login(tok1)
			c1.mustRegister(proto.KindHTTP, first.tunnel, 0)
		})
	}
}

// The bare name of a client is reserved for it from the moment its token exists, whether or not it has ever
// registered "ssh": client "web-b" (address "web-b") against client "b" with the tunnel "web" (HTTP label or ssh
// address "web-b"). Whatever the order of registrations, the squatter gets name_taken and the owner keeps its name.
func TestLabelClaimBareClientNameIsReserved(t *testing.T) {
	for _, victimFirst := range []bool{false, true} {
		for _, kind := range []string{proto.KindHTTP, proto.KindSSH} {
			name := kind + "_victim_last"
			if victimFirst {
				name = kind + "_victim_first"
			}
			t.Run(name, func(t *testing.T) {
				h := newHarness(t, withGateway)
				tokVictim := h.st.newToken(t, "web-b")
				tokAttacker := h.st.newToken(t, "b")
				register := func(c *client, tunnel string) proto.Message {
					if kind == proto.KindSSH {
						return c.registerSSH(tunnel, false)
					}
					return c.register(kind, tunnel, 0)
				}
				victim := func() {
					c := h.login(tokVictim)
					if _, ok := c.registerSSH("ssh", false).(*proto.Registered); !ok {
						t.Fatal("the owner of the name cannot register its ssh tunnel")
					}
					goOffline(t, h, c)
				}
				if victimFirst {
					victim()
				}
				c := h.login(tokAttacker)
				wantNameTaken(t, asErr(t, register(c, "web")))
				goOffline(t, h, c)
				if !victimFirst {
					victim()
				}
				// Nothing is left of the refused attempt: the second try is refused as well, after a restart too.
				if err := h.srv.Close(); err != nil {
					t.Fatal(err)
				}
				h2 := restart(t, h, withGateway)
				c = h2.login(tokAttacker)
				wantNameTaken(t, asErr(t, register(c, "web")))
				c = h2.login(tokVictim)
				if _, ok := c.registerSSH("ssh", false).(*proto.Registered); !ok {
					t.Fatal("the owner lost its name")
				}
			})
		}
	}
}

func asErr(t *testing.T, m proto.Message) *proto.Error {
	t.Helper()
	e, ok := m.(*proto.Error)
	if !ok {
		t.Fatalf("got %#v, want an error", m)
	}
	return e
}

// Revoking the owner's token frees its names; so does an explicit release.
func TestLabelClaimReleased(t *testing.T) {
	h := newHarness(t)
	tokHome := h.st.newToken(t, "home")
	tokA := h.st.newToken(t, "a-home")
	c := h.login(tokHome)
	c.mustRegister(proto.KindHTTP, "web-a", 0)
	goOffline(t, h, c)

	c2 := h.login(tokA)
	wantNameTaken(t, c2.registerErr(proto.KindHTTP, "web", 0))

	if err := h.st.ReleaseLabel(context.Background(), "web-a-home"); err != nil {
		t.Fatal(err)
	}
	c2.mustRegister(proto.KindHTTP, "web", 0)

	// Revocation: a third pair loses, the owner's token is revoked, the label is free.
	h = newHarness(t)
	tokHome = h.st.newToken(t, "home")
	tokA = h.st.newToken(t, "a-home")
	c = h.login(tokHome)
	c.mustRegister(proto.KindHTTP, "web-a", 0)
	goOffline(t, h, c)
	if err := h.st.RevokeToken(context.Background(), "home", h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	h.login(tokA).mustRegister(proto.KindHTTP, "web", 0)
}

// A registration that fails for another reason must not leave a claim behind.
func TestLabelClaimNotLeftByFailedRegistration(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home", func(tk *store.Token) { tk.MaxTunnels = 1 }))
	c.mustRegister(proto.KindHTTP, "one", 0)
	if e := c.registerErr(proto.KindHTTP, "two", 0); e.Code != proto.CodeLimitExceeded {
		t.Fatalf("got %+v, want limit_exceeded", e)
	}
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	if _, ok := h.st.claims["two-home"]; ok {
		t.Error("a failed registration left a claim")
	}
	if _, ok := h.st.claims["one-home"]; !ok {
		t.Error("the successful registration has no claim")
	}
}

func withClaimLimit(n int) func(*config.Config, *Options) {
	return func(c *config.Config, _ *Options) { c.Limits.MaxLabelClaimsPerClient = n }
}

// A client may not accumulate permanent names without bound by registering and closing tunnels with new names.
func TestLabelClaimLimitPerClient(t *testing.T) {
	h := newHarness(t, withClaimLimit(3))
	tok := h.st.newToken(t, "home")
	c := h.login(tok)
	for _, n := range []string{"a", "b", "c"} {
		c.mustRegister(proto.KindHTTP, n, 0)
	}
	e := c.registerErr(proto.KindHTTP, "d", 0)
	if e.Code != proto.CodeLimitExceeded || !strings.Contains(e.Message, "maximum of 3") {
		t.Fatalf("got %+v, want limit_exceeded naming the limit", e)
	}
	// An already held name is no new claim, and another client has its own budget.
	c.close()
	waitFor(t, "session gone", func() bool { return h.srv.sessionCount() == 0 })
	c = h.login(tok)
	c.mustRegister(proto.KindHTTP, "a", 0)
	h.login(h.st.newToken(t, "other")).mustRegister(proto.KindHTTP, "d", 0)
}

func TestLabelClaimDefaultLimit(t *testing.T) {
	h := newHarness(t)
	if want := max(minLabelClaimsPerClient, 4*h.cfg.MaxTunnelsPerClient); h.srv.maxClaims != want {
		t.Fatalf("default limit %d, want %d", h.srv.maxClaims, want)
	}
	h = newHarness(t, withClaimLimit(-1))
	if h.srv.maxClaims != 0 {
		t.Fatalf("a negative limit must turn the check off, got %d", h.srv.maxClaims)
	}
}

// Names that no registration has used for the claim TTL are dropped: they stop counting against the limit and
// become free for others; names that were used again stay. The label "w-<x>-home" of client "home" can also be
// composed by client "<x>-home" with the tunnel "w".
func TestLabelClaimExpires(t *testing.T) {
	h := newHarness(t, withClaimLimit(3))
	tokHome := h.st.newToken(t, "home")
	c := h.login(tokHome)
	for _, n := range []string{"w-a", "w-b", "w-c"} {
		c.mustRegister(proto.KindHTTP, n, 0)
	}
	if e := c.registerErr(proto.KindHTTP, "w-d", 0); e.Code != proto.CodeLimitExceeded {
		t.Fatalf("got %+v, want limit_exceeded before the claims expire", e)
	}
	goOffline(t, h, c)
	h.clock.advance(defaultLabelClaimTTL - time.Hour)
	c = h.login(tokHome)
	c.mustRegister(proto.KindHTTP, "w-a", 0) // used again: its claim lives on
	h.clock.advance(2 * time.Hour)           // "w-b" and "w-c" are now unused for longer than the TTL

	// At the limit, the sweep makes room for new names.
	c.mustRegister(proto.KindHTTP, "w-d", 0)
	c.mustRegister(proto.KindHTTP, "w-e", 0)
	if e := c.registerErr(proto.KindHTTP, "w-f", 0); e.Code != proto.CodeLimitExceeded {
		t.Fatalf("got %+v, want limit_exceeded again", e)
	}

	// The expired name is free for the other pair, the used one is not.
	wantNameTaken(t, h.login(h.st.newToken(t, "a-home")).registerErr(proto.KindHTTP, "w", 0))
	h.login(h.st.newToken(t, "b-home")).mustRegister(proto.KindHTTP, "w", 0)
}

// A tunnel that stays online keeps its names however long that is, and a restart does not drop them either.
func TestLabelClaimOfLiveTunnelDoesNotExpire(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "w-a", 0)
	h.clock.advance(defaultLabelClaimTTL + 24*time.Hour)
	// Any registration runs the lazy sweep; the live claim must survive it.
	h.login(h.st.newToken(t, "x")).mustRegister(proto.KindHTTP, "y", 0)
	wantNameTaken(t, h.login(h.st.newToken(t, "a-home")).registerErr(proto.KindHTTP, "w", 0))
}

// A dying session's failed registration must not take back a claim that the reconnected session of the same client
// already serves (the second registration found the claim in place and created none of its own).
func TestLabelClaimKeptWhenServedByAnotherSession(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "one", 0)

	h.srv.unclaimLabels("home", "one", []string{"one-home"}) // what the failed registration of the old session does
	if !h.srv.persist.flush(5 * time.Second) {
		t.Fatal("store writes did not finish")
	}
	h.st.mu.Lock()
	_, ok := h.st.claims["one-home"]
	h.st.mu.Unlock()
	if !ok {
		t.Error("the claim of a live tunnel was taken back")
	}

	h.srv.unclaimLabels("home", "two", []string{"two-home"}) // nobody serves it: the claim (if any) goes
	if !h.srv.persist.flush(5 * time.Second) {
		t.Fatal("store writes did not finish")
	}
}
