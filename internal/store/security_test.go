// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A3: revoking a token also revokes the join codes it created and has not used yet.
func TestRevokeTokenRevokesItsPendingJoinCodes(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, newTok("creator00001", "agent", t0)); err != nil {
		t.Fatal(err)
	}
	pending, _ := newJoin(t, s, "one", func(j *JoinCode) { j.CreatedBy = "creator00001" })
	used, code := newJoin(t, s, "two", func(j *JoinCode) { j.CreatedBy = "creator00001" })
	other, _ := newJoin(t, s, "three", func(j *JoinCode) { j.CreatedBy = "socket" })
	if _, _, err := s.RedeemJoinCode(ctx, used.ID, code.Secret, t0); err != nil {
		t.Fatal(err)
	}

	// By name, as the CLI does.
	if err := s.RevokeToken(ctx, "agent", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	codes, err := s.ListJoinCodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range codes {
		switch c.ID {
		case pending.ID:
			if c.RevokedAt == nil {
				t.Errorf("pending code of the revoked creator is still redeemable: %+v", c)
			}
		case used.ID:
			if c.RevokedAt != nil || c.UsedAt == nil {
				t.Errorf("used code changed: %+v", c)
			}
		case other.ID:
			if c.RevokedAt != nil {
				t.Errorf("code of another creator was revoked: %+v", c)
			}
		}
	}
}

// A3: tokens made by a link remember their creator; RevokeTokenCascade revokes the whole tree.
func TestRedeemSetsCreatedByAndCascade(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, newTok("creator00001", "agent", t0)); err != nil {
		t.Fatal(err)
	}
	mint := func(name, by string) *Token {
		jc, code := newJoin(t, s, name, func(j *JoinCode) { j.CreatedBy = by })
		tok, _, err := s.RedeemJoinCode(ctx, jc.ID, code.Secret, t0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.GetToken(ctx, tok.ID)
		if err != nil || got.CreatedBy != by {
			t.Fatalf("created_by = %q (%v), want %q", got.CreatedBy, err, by)
		}
		return tok
	}
	child := mint("child", "creator00001")
	grandchild := mint("grandchild", child.ID)
	bystander := mint("bystander", "socket")

	// Plain revoke keeps the children.
	if err := s.RevokeToken(ctx, "creator00001", t0); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetToken(ctx, child.ID); got.RevokedAt != nil {
		t.Fatal("plain revoke must not touch minted tokens")
	}

	ids, err := s.RevokeTokenCascade(ctx, "creator00001", t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Errorf("cascade revoked %v, want the creator, child and grandchild", ids)
	}
	for _, id := range []string{child.ID, grandchild.ID} {
		if got, _ := s.GetToken(ctx, id); got.RevokedAt == nil {
			t.Errorf("token %s survived the cascade", id)
		}
	}
	if got, _ := s.GetToken(ctx, bystander.ID); got.RevokedAt != nil {
		t.Error("cascade revoked an unrelated token")
	}
}

// A7: repeated denied entries of one actor are written once per window, with the number of suppressed repeats.
func TestAuditDeniedRateLimited(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	for i := range 500 {
		e := &AuditEntry{At: t0.Add(time.Duration(i) * time.Millisecond), Actor: "tok1", Action: "client.disconnect", Args: `{"remote":"1.2.3.4"}`, Result: "denied"}
		if err := s.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// Another actor and real actions are unaffected.
	_ = s.AppendAudit(ctx, &AuditEntry{At: t0, Actor: "tok2", Action: "x", Result: "denied"})
	_ = s.AppendAudit(ctx, &AuditEntry{At: t0, Actor: "tok1", Action: "token.revoke", Result: "ok"})
	// The next window reports how many were dropped.
	_ = s.AppendAudit(ctx, &AuditEntry{At: t0.Add(2 * time.Minute), Actor: "tok1", Action: "client.disconnect", Args: `{"remote":"1.2.3.4"}`, Result: "denied"})

	got, err := s.ListAudit(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("%d rows, want 4 (one denied per actor and window, plus the ok row): %+v", len(got), got)
	}
	if !strings.Contains(got[0].Args, `"suppressed":499`) || !strings.Contains(got[0].Args, `"remote":"1.2.3.4"`) {
		t.Errorf("summary row args = %s, want suppressed 499 and the original fields", got[0].Args)
	}
}

// A7: ring retention.
func TestAuditRetention(t *testing.T) {
	s, _ := openTemp(t)
	s.SetAuditMaxRows(50)
	ctx := context.Background()
	for i := range 400 {
		if err := s.AppendAudit(ctx, &AuditEntry{At: t0, Actor: "socket", Action: fmt.Sprintf("a%d", i), Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListAudit(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	// Pruning runs every few inserts, so the log may overshoot slightly, but never grows without bound.
	if len(got) < 50 || len(got) > 50+auditPruneEvery {
		t.Fatalf("%d rows, want 50..%d", len(got), 50+auditPruneEvery)
	}
	if got[0].Action != "a399" {
		t.Errorf("newest = %q, the newest entry must survive", got[0].Action)
	}
}

// A7: paging with before.
func TestListAuditBefore(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	for i := range 7 {
		_ = s.AppendAudit(ctx, &AuditEntry{At: t0, Actor: "socket", Action: fmt.Sprintf("a%d", i), Result: "ok"})
	}
	page1, err := s.ListAuditBefore(ctx, 0, 3)
	if err != nil || len(page1) != 3 || page1[0].Action != "a6" {
		t.Fatalf("page 1: %+v, %v", page1, err)
	}
	page2, err := s.ListAuditBefore(ctx, page1[2].ID, 3)
	if err != nil || len(page2) != 3 || page2[0].Action != "a3" || page2[2].Action != "a1" {
		t.Fatalf("page 2: %+v, %v", page2, err)
	}
	page3, err := s.ListAuditBefore(ctx, page2[2].ID, 3)
	if err != nil || len(page3) != 1 || page3[0].Action != "a0" {
		t.Fatalf("page 3: %+v, %v", page3, err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("unexpected")
	}
}
