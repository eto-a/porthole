// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestClaimLabels(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)

	got, err := s.ClaimLabels(ctx, "home", "web-a", []string{"web-a-home"}, t0, 0)
	if err != nil || !slices.Equal(got, []string{"web-a-home"}) {
		t.Fatalf("first claim: %v %v", got, err)
	}
	// The same pair again: nothing new, no error.
	got, err = s.ClaimLabels(ctx, "home", "web-a", []string{"web-a-home"}, t0, 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("repeated claim: %v %v", got, err)
	}
	// The other pair that composes the same label loses, and a failed call claims nothing.
	if _, err = s.ClaimLabels(ctx, "a-home", "web", []string{"fresh-label", "web-a-home"}, t0, 0); !errors.Is(err, ErrLabelClaimed) {
		t.Fatalf("second pair: %v, want ErrLabelClaimed", err)
	}
	if _, err = s.ClaimLabels(ctx, "a-home", "other", []string{"fresh-label"}, t0, 0); err != nil {
		t.Fatalf("a failed claim must not leave its other labels behind: %v", err)
	}

	// The claim survives a reopen of the database (server restart).
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err = s2.ClaimLabels(ctx, "a-home", "web", []string{"web-a-home"}, t0, 0); !errors.Is(err, ErrLabelClaimed) {
		t.Fatalf("after reopen: %v, want ErrLabelClaimed", err)
	}

	// Unclaim only touches the caller's own claims.
	if err := s2.UnclaimLabels(ctx, "a-home", "web", []string{"web-a-home"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s2.ClaimLabels(ctx, "a-home", "web", []string{"web-a-home"}, t0, 0); !errors.Is(err, ErrLabelClaimed) {
		t.Fatalf("unclaim by a stranger removed the claim: %v", err)
	}
	if err := s2.ReleaseLabel(ctx, "web-a-home"); err != nil {
		t.Fatal(err)
	}
	if err := s2.ReleaseLabel(ctx, "web-a-home"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second release: %v, want ErrNotFound", err)
	}
	if _, err = s2.ClaimLabels(ctx, "a-home", "web", []string{"web-a-home"}, t0, 0); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestRevokeTokenReleasesLabels(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "home", t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimLabels(ctx, "home", "web-a", []string{"web-a-home"}, t0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimLabels(ctx, "other", "x", []string{"x-other"}, t0, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ctx, "home", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimLabels(ctx, "a-home", "web", []string{"web-a-home"}, t0, 0); err != nil {
		t.Fatalf("the label of a revoked client must be free: %v", err)
	}
	if _, err := s.ClaimLabels(ctx, "y", "x", []string{"x-other"}, t0, 0); !errors.Is(err, ErrLabelClaimed) {
		t.Fatalf("a revoked token released the labels of another client: %v", err)
	}
}

func TestTokenNameMayNotBeAnotherClientsLabel(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if _, err := s.ClaimLabels(ctx, "b", "a", []string{"a-b"}, t0, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "a-b", t0)); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("CreateToken: %v, want ErrNameTaken", err)
	}
	jc := &JoinCode{ID: "jjjjjjjjjjjj", CodeHash: []byte("0123456789abcdef0123456789abcdef"), ClientName: "a-b", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
	if err := s.CreateJoinCode(ctx, jc); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("CreateJoinCode: %v, want ErrNameTaken", err)
	}
	// A client's own label is no obstacle for its own name, and unrelated names are free.
	if err := s.CreateToken(ctx, newTok("bbbbbbbbbbbb", "b", t0)); err != nil {
		t.Fatalf("unrelated name: %v", err)
	}
	if err := s.ReleaseLabel(ctx, "a-b"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "a-b", t0)); err != nil {
		t.Fatalf("after release: %v", err)
	}
}
