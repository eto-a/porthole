// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/traffic"
)

// A6: revoking through the admin API ends the token's live session at once, not at the next revalidation.
func TestAdminRevokeClosesSessionAtOnce(t *testing.T) {
	h := newHarness(t)
	admin := h.st.newToken(t, "agent", func(tok *store.Token) { tok.Scopes = []string{auth.ScopeAdminTokens} })
	victim := h.st.newToken(t, "home")
	c := h.login(victim)
	c.mustRegister(proto.KindHTTP, "web", 0)

	// The harness revalidates every 30 s by default; waitClosed gives up after 5 s.
	if status, body := adminDo(t, h, "POST", "/tokens/"+victim.id+"/revoke", admin.str); status != http.StatusOK {
		t.Fatalf("revoke: %d %s", status, body)
	}
	_ = c.expectFatal(proto.CodeTokenRevoked)
	waitFor(t, "session removal", func() bool { return h.srv.sessionCount() == 0 && h.srv.tunnelCount() == 0 })
}

// Info (I3): a token that holds only admin scopes is for the admin API, not for a client session.
func TestAdminOnlyTokenCannotOpenSession(t *testing.T) {
	h := newHarness(t)
	admin := h.st.newToken(t, "agent", func(tok *store.Token) { tok.Scopes = []string{auth.ScopeAdminRead, auth.ScopeAdminRemote} })
	_ = wantError(t, rawHandshake(t, h.wsURL, goodHello(admin.str)), proto.CodeForbidden, true)
	if h.srv.sessionCount() != 0 {
		t.Error("an admin-only token got a session")
	}
	// It still works on the admin API.
	if status, _ := adminDo(t, h, "GET", "/status", admin.str); status != http.StatusOK {
		t.Errorf("admin API with the same token: %d", status)
	}
	// A token with a connect scope only (SSH gateway) is not a client either.
	conn := h.st.newToken(t, "ssh-only", func(tok *store.Token) { tok.Scopes = []string{"connect:home"} })
	_ = wantError(t, rawHandshake(t, h.wsURL, goodHello(conn.str)), proto.CodeForbidden, true)
}

// N-08: a replay goes to the tunnel it was recorded on (or, after a reconnect, to a tunnel of the same client), never
// to another client that holds the same hostname label. Labels are name + "-" + client, so client "a-b" with tunnel
// "c" and client "b" with tunnel "c-a" both own "c-a-b".
func TestReplayNotSentToAnotherOwner(t *testing.T) {
	h := newHarness(t)
	backend, _ := inspBackend(t, 0)
	owner := h.login(h.st.newToken(t, "a-b"))
	owner.registerInspect(proto.KindHTTP, "c")
	owner.serve(forward(backend.Listener.Addr().String()))
	h.visit("c-a-b.example.test", http.MethodPost, "/pay", `{"card":"4242"}`, map[string]string{"X-Custom": "kept"})
	orig := waitRequests(t, h.srv, traffic.RequestFilter{}, 1)[0]

	owner.close()
	waitFor(t, "owner gone", func() bool { return h.srv.sessionCount() == 0 })

	evilBackend, evilSeen := inspBackend(t, 0)
	evil := h.login(h.st.newToken(t, "b"))
	evil.registerInspect(proto.KindHTTP, "c-a")
	evil.serve(forward(evilBackend.Listener.Addr().String()))

	_, err := h.srv.ReplayRequest(context.Background(), orig.ID)
	if !errors.Is(err, ErrReplayRefused) {
		t.Errorf("replay to another client's tunnel: %v, want a refusal", err)
	}
	if n := len(evilSeen()); n != 0 {
		t.Errorf("the other client's service received %d replayed request(s)", n)
	}

	// The same client coming back (new session, new tunnel id) is fine.
	evil.close()
	waitFor(t, "evil gone", func() bool { return h.srv.sessionCount() == 0 })
	back := h.login(h.st.newToken(t, "a-b-again", func(tok *store.Token) { tok.Name = "a-b" }))
	back.registerInspect(proto.KindHTTP, "c")
	back.serve(forward(backend.Listener.Addr().String()))
	if _, err := h.srv.ReplayRequest(context.Background(), orig.ID); err != nil {
		t.Errorf("replay after the owner reconnected: %v", err)
	}
}
