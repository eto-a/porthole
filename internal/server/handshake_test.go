// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/transport"
)

func wantError(t *testing.T, m proto.Message, code string, fatal bool) *proto.Error {
	t.Helper()
	e, ok := m.(*proto.Error)
	if !ok {
		t.Fatalf("got %#v, want error %s", m, code)
	}
	if e.Code != code || e.Fatal != fatal {
		t.Fatalf("got error %+v, want code %s fatal=%v", e, code, fatal)
	}
	return e
}

func TestHandshakeOK(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.HeartbeatInterval = 1500 * time.Millisecond })
	tok := h.st.newToken(t, "home")
	c := h.login(tok)
	if c.ok.ClientName != "home" {
		t.Errorf("client_name = %q, want home", c.ok.ClientName)
	}
	if c.ok.SessionID == "" || c.ok.ServerVersion != "test" || c.ok.HeartbeatIntervalMS != 1500 {
		t.Errorf("unexpected hello_ok: %+v", c.ok)
	}
	if !h.st.wasTouched(tok.id) {
		t.Error("token was not touched")
	}
	waitFor(t, "session registration", func() bool { return h.srv.sessionCount() == 1 })
}

func TestHandshakeRejects(t *testing.T) {
	h := newHarness(t)
	tok := h.st.newToken(t, "home")
	other, err := auth.Generate() // well-formed token that the store does not know
	if err != nil {
		t.Fatal(err)
	}
	wrongSecret, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	wrongSecret.ID = tok.id

	cases := map[string]string{
		"unknown id":   other.String(),
		"wrong secret": wrongSecret.String(),
		"malformed":    "not-a-token",
		"empty":        "",
	}
	var msgs []string
	for name, token := range cases {
		e := wantError(t, rawHandshake(t, h.wsURL, goodHello(token)), proto.CodeUnauthorized, true)
		msgs = append(msgs, e.Message)
		t.Logf("%s: %s", name, e.Message)
	}
	for _, m := range msgs[1:] {
		if m != msgs[0] {
			t.Errorf("unauthorized messages differ (%q vs %q): reason would leak", m, msgs[0])
		}
	}
	if h.srv.sessionCount() != 0 {
		t.Error("a failed handshake left a session behind")
	}
}

func TestHandshakeUnsupportedVersion(t *testing.T) {
	h := newHarness(t)
	tok := h.st.newToken(t, "home")
	for _, v := range []int{0, proto.Version + 1, 99} {
		hello := goodHello(tok.str)
		hello.ProtocolVersion = v
		e := wantError(t, rawHandshake(t, h.wsURL, hello), proto.CodeUnsupportedVersion, true)
		if !strings.Contains(e.Message, "1..1") {
			t.Errorf("message %q does not name the supported range", e.Message)
		}
	}
}

func TestHandshakeRevokedAndExpired(t *testing.T) {
	h := newHarness(t)
	now := h.clock.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	revoked := h.st.newToken(t, "gone", func(tk *store.Token) { tk.RevokedAt = &past })
	expired := h.st.newToken(t, "old", func(tk *store.Token) { tk.ExpiresAt = &past })
	valid := h.st.newToken(t, "fresh", func(tk *store.Token) { tk.ExpiresAt = &future })

	_ = wantError(t, rawHandshake(t, h.wsURL, goodHello(revoked.str)), proto.CodeTokenRevoked, true)
	_ = wantError(t, rawHandshake(t, h.wsURL, goodHello(expired.str)), proto.CodeTokenExpired, true)
	if _, ok := rawHandshake(t, h.wsURL, goodHello(valid.str)).(*proto.HelloOK); !ok {
		t.Error("token with a future expiry was rejected")
	}
}

func TestHandshakeFailureRateLimit(t *testing.T) {
	h := newHarness(t)
	good := h.st.newToken(t, "home")
	unknown, err := auth.Generate() // well-formed but not in the store
	if err != nil {
		t.Fatal(err)
	}
	bad := goodHello(unknown.String())
	for i := range failBurst {
		if _, ok := rawHandshake(t, h.wsURL, bad).(*proto.Error); !ok {
			t.Fatalf("attempt %d: want error", i)
		}
	}
	e := wantError(t, rawHandshake(t, h.wsURL, bad), proto.CodeLimitExceeded, true)
	if e.RetryAfterMS <= 0 {
		t.Errorf("retry_after_ms = %d, want > 0", e.RetryAfterMS)
	}
	// The budget is per source address, so even a valid token is held back until it recovers.
	_ = wantError(t, rawHandshake(t, h.wsURL, goodHello(good.str)), proto.CodeLimitExceeded, true)

	// Time passing restores the budget.
	h.clock.advance(time.Duration(e.RetryAfterMS+1000) * time.Millisecond)
	if _, ok := rawHandshake(t, h.wsURL, goodHello(good.str)).(*proto.HelloOK); !ok {
		t.Error("valid token still refused after the wait")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.HandshakeTimeout = 100 * time.Millisecond })
	ts, ctrl := dialSession(t, h.wsURL, transport.DialOptions{})
	defer ts.Close()
	_ = ctrl // opened but silent: never sends hello
	select {
	case <-ts.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server did not close a session that never sent hello")
	}
}

func TestSecondClientStreamClosesSession(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	st, err := c.ts.Open()
	if err != nil {
		t.Fatal(err)
	}
	_ = st
	_ = c.expectFatal(proto.CodeInvalidRequest)
	waitFor(t, "session removal", func() bool { return h.srv.sessionCount() == 0 })
}

func TestUnknownControlMessageIgnored(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	if err := writeRawFrame(c, `{"type":"from_the_future","x":1}`); err != nil {
		t.Fatal(err)
	}
	c.mustRegister(proto.KindHTTP, "web", 0) // the session still works
}
