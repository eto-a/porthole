// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A client name is reserved for its token from the moment the token exists: another client must not be able to
// compose it as "<tunnel>-<client>" first (the SSH gateway would send "ssh <name>" to the squatter).
func TestClaimLabelsRefusesAnotherClientsName(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "web-b", t0)); err != nil {
		t.Fatal(err)
	}
	// Client b registers the ssh tunnel "web": its address would be "web-b", the name of the victim.
	if _, err := s.ClaimLabels(ctx, "b", "web", []string{"web-b"}, t0, 0); !errors.Is(err, ErrLabelClaimed) {
		t.Fatalf("squatting the name of an existing client: %v, want ErrLabelClaimed", err)
	}
	// The victim keeps its own names, also the bare one for its tunnel "ssh".
	if _, err := s.ClaimLabels(ctx, "web-b", "ssh", []string{"ssh-web-b", "web-b"}, t0, 0); err != nil {
		t.Fatalf("the owner of the name: %v", err)
	}
}

// The other order (the claim first, the token later) is refused by CreateToken, see
// TestTokenNameMayNotBeAnotherClientsLabel. Revoking the token frees the name.
func TestClaimLabelsNameOfRevokedClientIsFree(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "web-b", t0)); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ctx, "web-b", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimLabels(ctx, "b", "web", []string{"web-b"}, t0, 0); err != nil {
		t.Fatalf("the name of a revoked client must be free: %v", err)
	}
	// ... and the name is a client name again only for a new token, which then collides with the claim.
	if err := s.CreateToken(ctx, newTok("cccccccccccc", "web-b", t0)); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("CreateToken over a live claim: %v, want ErrNameTaken", err)
	}
}

// A token that existed before the check was introduced is covered without any data migration: the reservation is
// derived from the tokens table.
func TestClaimLabelsCoversTokensFromBeforeTheCheck(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, name, secret_hash, last4, scopes, max_tunnels, created_at) VALUES ('old', 'web-b', x'00', 'abcd', 'tunnel', 0, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimLabels(ctx, "b", "web", []string{"web-b"}, t0, 0); !errors.Is(err, ErrLabelClaimed) {
		t.Fatalf("pre-existing token: %v, want ErrLabelClaimed", err)
	}
}

func TestClaimLabelsLimit(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for _, l := range []string{"a-home", "b-home", "c-home"} {
		if _, err := s.ClaimLabels(ctx, "home", l[:1], []string{l}, t0, 3); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
	}
	if _, err := s.ClaimLabels(ctx, "home", "d", []string{"d-home"}, t0, 3); !errors.Is(err, ErrLabelLimit) {
		t.Fatalf("over the limit: %v, want ErrLabelLimit", err)
	}
	// The refused claim left nothing behind, existing claims still work, and other clients have their own budget.
	if _, err := s.ClaimLabels(ctx, "home", "a", []string{"a-home"}, t0, 3); err != nil {
		t.Fatalf("an existing claim must not count again: %v", err)
	}
	if _, err := s.ClaimLabels(ctx, "other", "d", []string{"d-other"}, t0, 3); err != nil {
		t.Fatalf("other client: %v", err)
	}
	// 0 means no limit.
	if _, err := s.ClaimLabels(ctx, "home", "d", []string{"d-home"}, t0, 0); err != nil {
		t.Fatalf("no limit: %v", err)
	}
	// Releasing one frees room.
	if err := s.UnclaimLabels(ctx, "home", "d", []string{"d-home"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimLabels(ctx, "home", "e", []string{"e-home"}, t0, 4); err != nil {
		t.Fatalf("after unclaim: %v", err)
	}
}

func TestExpireLabelClaims(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	const ttl = 30 * 24 * time.Hour
	claim := func(client, tunnel, label string, at time.Time) {
		t.Helper()
		if _, err := s.ClaimLabels(ctx, client, tunnel, []string{label}, at, 0); err != nil {
			t.Fatal(err)
		}
	}
	claim("home", "old", "old-home", t0)     // never used again
	claim("home", "used", "used-home", t0)   // registered again later
	claim("home", "live", "live-home", t0)   // online the whole time
	claim("home", "fresh", "fresh-home", t0) // claimed late
	later := t0.Add(ttl - time.Hour)
	claim("home", "used", "used-home", later)
	claim("home", "fresh", "fresh-home", later)

	now := t0.Add(ttl + time.Hour)
	n, err := s.ExpireLabelClaims(ctx, now, ttl, []ClaimOwner{{Client: "home", Tunnel: "live"}})
	if err != nil || n != 1 {
		t.Fatalf("expired %d, %v; want 1 (only old-home)", n, err)
	}
	// old-home is free for another pair; the others still belong to home.
	claim("a-home", "old", "old-home", now)
	for _, l := range []string{"used-home", "live-home", "fresh-home"} {
		if _, err := s.ClaimLabels(ctx, "x", "y", []string{l}, now, 0); !errors.Is(err, ErrLabelClaimed) {
			t.Fatalf("%s: %v, want ErrLabelClaimed", l, err)
		}
	}
	if n, err := s.ExpireLabelClaims(ctx, now.Add(ttl), 0, nil); err != nil || n != 0 {
		t.Fatalf("ttl 0 must expire nothing: %d %v", n, err)
	}
	// A row from before the migration has no last_used_at: claimed_at counts.
	if _, err := s.db.ExecContext(ctx, `UPDATE label_claims SET last_used_at = NULL WHERE label = 'fresh-home'`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireLabelClaims(ctx, now, ttl, nil); err != nil || n != 1 {
		t.Fatalf("NULL last_used_at: expired %d, %v; want 1", n, err)
	}
}
