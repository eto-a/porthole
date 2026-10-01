// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"testing"

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

// The same holds for the SSH gateway, where the bare client name of the tunnel "ssh" shares the namespace with the
// labels "<tunnel>-<client>": client "a-b" (bare name "a-b") against client "b" with the ssh tunnel "a" (label "a-b").
func TestLabelClaimSSHBareNameAgainstLabel(t *testing.T) {
	type pair struct{ client, tunnel string }
	bare, labelled := pair{"a-b", "ssh"}, pair{"b", "a"}
	for _, order := range [][2]pair{{bare, labelled}, {labelled, bare}} {
		first, second := order[0], order[1]
		t.Run(first.client+"_first", func(t *testing.T) {
			h := newHarness(t, withGateway)
			tok1 := h.st.newToken(t, first.client)
			tok2 := h.st.newToken(t, second.client)

			c1 := h.login(tok1)
			if _, ok := c1.registerSSH(first.tunnel, false).(*proto.Registered); !ok {
				t.Fatal("first ssh registration failed")
			}
			goOffline(t, h, c1)

			c2 := h.login(tok2)
			wantNameTaken(t, asErr(t, c2.registerSSH(second.tunnel, false)))
			c2.close()
			waitFor(t, "session gone", func() bool { return h.srv.sessionCount() == 0 })

			if err := h.srv.Close(); err != nil {
				t.Fatal(err)
			}
			h2 := restart(t, h, withGateway)
			c2 = h2.login(tok2)
			wantNameTaken(t, asErr(t, c2.registerSSH(second.tunnel, false)))
			c1 = h2.login(tok1)
			if _, ok := c1.registerSSH(first.tunnel, false).(*proto.Registered); !ok {
				t.Fatal("the owner lost its ssh name after a restart")
			}
		})
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
