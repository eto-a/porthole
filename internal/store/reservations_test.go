// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

const testTTL = 24 * time.Hour

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func countReservations(t *testing.T, s *SQLite) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM port_reservations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMigrationAppliesToEmptyAndToV1(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	if got := countReservations(t, s); got != 0 {
		t.Fatalf("fresh database has %d reservations", got)
	}

	// Roll the database back to the state of release 0001, then open it again.
	if _, err := s.db.ExecContext(ctx, `DROP TABLE port_reservations`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "home", t0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open v1 database: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if err := s2.HoldPort(ctx, "home", "ssh", 20001, t0, testTTL); err != nil {
		t.Fatalf("HoldPort after migration: %v", err)
	}
	if _, err := s2.GetToken(ctx, "aaaaaaaaaaaa"); err != nil {
		t.Errorf("token lost by migration: %v", err)
	}
	var n int
	if err := s2.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != len(testMigrations(t)) {
		t.Errorf("schema_migrations rows = %d, %v; want %d", n, err, len(testMigrations(t)))
	}
}

func TestHoldReleaseLoad(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	for _, r := range []struct {
		client, tunnel string
		port           int
	}{{"home", "ssh", 20001}, {"home", "db", 20002}, {"work", "ssh", 20003}} {
		if err := s.HoldPort(ctx, r.client, r.tunnel, r.port, t0, testTTL); err != nil {
			t.Fatal(err)
		}
	}
	// Re-holding the same tunnel is an upsert and may change the port.
	if err := s.HoldPort(ctx, "home", "db", 20004, t0, testTTL); err != nil {
		t.Fatalf("re-hold: %v", err)
	}
	if got := countReservations(t, s); got != 3 {
		t.Fatalf("rows = %d, want 3", got)
	}
	if err := s.ReleasePort(ctx, "work", "ssh", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleasePort(ctx, "nobody", "nothing", t0); err != nil {
		t.Errorf("releasing an unknown tunnel: %v", err)
	}

	// Start 2 hours later: NULL rows are released "now", the one released earlier keeps its time.
	now := t0.Add(2 * time.Hour)
	got, err := s.LoadPortReservations(ctx, now, testTTL)
	if err != nil {
		t.Fatal(err)
	}
	want := []PortReservation{
		{Client: "home", Tunnel: "db", Port: 20004, ReleasedAt: now},
		{Client: "home", Tunnel: "ssh", Port: 20001, ReleasedAt: now},
		{Client: "work", Tunnel: "ssh", Port: 20003, ReleasedAt: t0.Add(time.Hour)},
	}
	if len(got) != len(want) {
		t.Fatalf("loaded %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Nothing is live any more, so a second load changes nothing.
	again, err := s.LoadPortReservations(ctx, now.Add(time.Minute), testTTL)
	if err != nil || len(again) != 3 || again[0].ReleasedAt != now {
		t.Errorf("second load = %+v, %v", again, err)
	}
}

func TestLoadDeletesExpired(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for i, name := range []string{"a", "b", "c"} {
		if err := s.HoldPort(ctx, "home", name, 20001+i, t0, testTTL); err != nil {
			t.Fatal(err)
		}
	}
	// a: released exactly one TTL ago (expired, the boundary is exclusive), b: just inside it, c: still live.
	now := t0.Add(48 * time.Hour)
	if err := s.ReleasePort(ctx, "home", "a", now.Add(-testTTL)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleasePort(ctx, "home", "b", now.Add(-testTTL+time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadPortReservations(ctx, now, testTTL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Tunnel != "b" || got[1].Tunnel != "c" || got[1].ReleasedAt != now {
		t.Fatalf("loaded %+v, want b and c", got)
	}
	if n := countReservations(t, s); n != 2 {
		t.Errorf("rows after load = %d, want 2 (expired row deleted)", n)
	}
}

func TestHoldPortUniquePort(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.HoldPort(ctx, "home", "ssh", 20001, t0, testTTL); err != nil {
		t.Fatal(err)
	}

	// Live (NULL) and unexpired reservations block the port.
	err := s.HoldPort(ctx, "work", "ssh", 20001, t0, testTTL)
	if !errors.Is(err, ErrPortHeld) {
		t.Fatalf("port held by a live tunnel: got %v, want ErrPortHeld", err)
	}
	if err := s.ReleasePort(ctx, "home", "ssh", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.HoldPort(ctx, "work", "ssh", 20001, t0.Add(testTTL-time.Second), testTTL); !errors.Is(err, ErrPortHeld) {
		t.Fatalf("port reserved: got %v, want ErrPortHeld", err)
	}
	// The failed attempt left the owner alone.
	got, err := s.LoadPortReservations(ctx, t0.Add(time.Hour), testTTL)
	if err != nil || len(got) != 1 || got[0].Client != "home" {
		t.Fatalf("after failed hold: %+v, %v", got, err)
	}

	// Once the reservation expired, the port goes to the new tunnel and the old row is gone.
	if err := s.HoldPort(ctx, "work", "ssh", 20001, t0.Add(testTTL), testTTL); err != nil {
		t.Fatalf("expired reservation must give way: %v", err)
	}
	if n := countReservations(t, s); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}

	for _, bad := range []struct {
		client, tunnel string
		port           int
	}{{"", "t", 20001}, {"c", "", 20001}, {"c", "t", 0}, {"c", "t", 70000}} {
		if err := s.HoldPort(ctx, bad.client, bad.tunnel, bad.port, t0, testTTL); err == nil {
			t.Errorf("HoldPort(%q, %q, %d): want error", bad.client, bad.tunnel, bad.port)
		}
	}
}

func TestRevokeDeletesReservations(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for _, tok := range []*Token{newTok("aaaaaaaaaaaa", "home", t0), newTok("bbbbbbbbbbbb", "work", t0)} {
		if err := s.CreateToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	hold := func(client, tunnel string, port int) {
		t.Helper()
		if err := s.HoldPort(ctx, client, tunnel, port, t0, testTTL); err != nil {
			t.Fatal(err)
		}
	}
	hold("home", "ssh", 20001)
	hold("home", "db", 20002)
	hold("work", "ssh", 20003)

	// By id.
	if err := s.RevokeToken(ctx, "aaaaaaaaaaaa", t0); err != nil {
		t.Fatal(err)
	}
	if n := countReservations(t, s); n != 1 {
		t.Fatalf("rows after revoking home = %d, want 1", n)
	}

	// A new token takes the name over; revoking the old id again must not touch the newcomer's ports.
	if err := s.CreateToken(ctx, newTok("cccccccccccc", "home", t0)); err != nil {
		t.Fatal(err)
	}
	hold("home", "ssh", 20001)
	if err := s.RevokeToken(ctx, "aaaaaaaaaaaa", t0); err != nil {
		t.Fatal(err)
	}
	if n := countReservations(t, s); n != 2 {
		t.Fatalf("rows after idempotent revoke = %d, want 2", n)
	}

	// By name.
	if err := s.RevokeToken(ctx, "work", t0); err != nil {
		t.Fatal(err)
	}
	if n := countReservations(t, s); n != 1 {
		t.Fatalf("rows after revoking work = %d, want 1", n)
	}

	// An unknown token changes nothing.
	if err := s.RevokeToken(ctx, "ghost", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	if n := countReservations(t, s); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}
