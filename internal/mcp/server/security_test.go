// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/store"
)

// N-05: descriptions of mutating tools say to act only on the user's explicit request; tools that return visitor data
// say the data is untrusted.
func TestDescriptionsWarnAboutInjection(t *testing.T) {
	cs := connect(t, newServer(t, newFakeOps(), Options{}))
	res, err := cs.ListTools(ctxT(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	mutating := map[string]bool{"close_tunnel": true, "create_join_link": true, "disconnect_client": true, "replay_request": true, "request_tunnel": true, "revoke_token": true}
	visitor := map[string]bool{"query_requests": true, "get_request": true, "connection_log": true, "gateway_auth_failures": true}
	seenM, seenV := 0, 0
	for _, tl := range res.Tools {
		if mutating[tl.Name] {
			seenM++
			if !strings.Contains(tl.Description, "only when the user explicitly asks") {
				t.Errorf("%s: description lacks the explicit-request rule: %q", tl.Name, tl.Description)
			}
		}
		if visitor[tl.Name] {
			seenV++
			if !strings.Contains(tl.Description, "untrusted") {
				t.Errorf("%s: description lacks the untrusted-data note: %q", tl.Name, tl.Description)
			}
		}
	}
	if seenM != len(mutating) || seenV != len(visitor) {
		t.Errorf("saw %d mutating and %d visitor tools, want %d and %d", seenM, seenV, len(mutating), len(visitor))
	}
}

// N-05: results with visitor data carry the notice.
func TestVisitorResultsAreMarked(t *testing.T) {
	cs := connect(t, newServer(t, newFakeOps(), Options{}))
	for _, tool := range []string{"query_requests", "get_request", "connection_log", "gateway_auth_failures"} {
		args := map[string]any{}
		if tool == "get_request" {
			args["id"] = 7
		}
		var out map[string]any
		decode(t, call(t, cs, tool, args), &out)
		if n, _ := out["untrusted_notice"].(string); !strings.Contains(n, "untrusted") {
			t.Errorf("%s: untrusted_notice = %v", tool, out["untrusted_notice"])
		}
	}
}

type sessionBackend struct {
	adminapi.Backend
	mu      sync.Mutex
	revoked []string
}

func (b *sessionBackend) TokenRevoked(_ context.Context, id string) {
	b.mu.Lock()
	b.revoked = append(b.revoked, id)
	b.mu.Unlock()
}

type revokeStore struct {
	adminapi.Store
	mu      sync.Mutex
	revoked []string
}

func (s *revokeStore) GetToken(_ context.Context, id string) (*store.Token, error) {
	return &store.Token{ID: id}, nil
}

func (s *revokeStore) RevokeToken(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	s.revoked = append(s.revoked, id)
	s.mu.Unlock()
	return nil
}

// A6: revoking through the MCP tool closes the token's sessions at once.
func TestRevokeToolClosesSessions(t *testing.T) {
	be, st := &sessionBackend{}, &revokeStore{}
	ops := &LocalOps{Backend: be, Store: st}
	if err := ops.RevokeToken(tokenCtx("tok_a", auth.ScopeAdminTokens), "victim"); err != nil {
		t.Fatal(err)
	}
	if len(st.revoked) != 1 || len(be.revoked) != 1 || be.revoked[0] != "victim" {
		t.Errorf("store %v, backend %v; want the backend told about victim", st.revoked, be.revoked)
	}
}

func callerCtx(c caller) context.Context {
	return context.WithValue(context.Background(), callerKey{}, c)
}

// A3/A4 through the MCP tool: same limits as the admin API.
func TestCreateJoinLinkLimits(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Hour)
	c := caller{actor: "tok_a", scopes: []string{auth.ScopeAdminTokens, auth.ScopeAdminRead}, name: "laptop", expires: &exp}
	st := &joinStore{}
	ops := &LocalOps{Store: st, ServerURL: "https://tun.example.com", MaxTunnelsPerClient: 10, Now: func() time.Time { return now }}

	for _, sc := range []string{auth.ScopeAdminRead, auth.ScopeAdminTokens, "connect:prod-db"} {
		if _, err := ops.CreateJoinLink(callerCtx(c), JoinLinkParams{Client: "x", Scopes: []string{sc}}); err == nil {
			t.Errorf("scope %s was granted to a bearer caller", sc)
		}
	}
	if _, err := ops.CreateJoinLink(callerCtx(c), JoinLinkParams{Client: "own", Scopes: []string{"connect:laptop"}}); err != nil {
		t.Errorf("connect to the caller's own client: %v", err)
	}
	if _, err := ops.CreateJoinLink(callerCtx(c), JoinLinkParams{Client: "y", TTL: 5 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	last := st.codes[len(st.codes)-1]
	if last.ExpiresAt.After(exp) || last.TokenExpiresAt == nil || last.TokenExpiresAt.After(exp) {
		t.Errorf("link expires %v, token %v; the caller's token expires %v", last.ExpiresAt, last.TokenExpiresAt, exp)
	}
	// The trusted stdio caller is not limited.
	if _, err := ops.CreateJoinLink(callerCtx(caller{actor: DefaultActor, trusted: true}), JoinLinkParams{Client: "z", Scopes: []string{auth.ScopeAdminTokens}}); err != nil {
		t.Errorf("trusted caller: %v", err)
	}
}

// I2: mutating calls over HTTP record the caller's address.
func TestHTTPAuditRecordsRemote(t *testing.T) {
	aud := &fakeAudit{}
	ts := httpEnv(t, newFakeOps(), aud)
	cs := httpSession(t, ts, "tunnels")
	_ = call(t, cs, "close_tunnel", map[string]any{"id": "t1"})
	got := aud.get()
	if len(got) != 1 || !strings.Contains(got[0].Args, `"remote":"127.0.0.1"`) || !strings.Contains(got[0].Args, `"id":"t1"`) {
		t.Errorf("audit = %+v, want args with id and remote", got)
	}
}
