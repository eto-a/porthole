// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*SQLite, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data", "porthole.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func newTok(id, name string, created time.Time) *Token {
	return &Token{
		ID:         id,
		Name:       name,
		SecretHash: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Last4:      "abcd",
		Scopes:     []string{"tunnel:http", "tunnel:tcp"},
		MaxTunnels: 5,
		CreatedAt:  created,
	}
}

func TestOpenCreatesDirAndFile(t *testing.T) {
	_, path := openTemp(t)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if st.Size() == 0 {
		t.Error("database file is empty after Open")
	}
}

func TestPragmasApplyToEveryConnection(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	// Hold several connections at once so the pool opens more than one.
	var conns []interface{ Close() error }
	for range 4 {
		c, err := s.db.Conn(ctx)
		if err != nil {
			t.Fatalf("Conn: %v", err)
		}
		conns = append(conns, c)
		var mode string
		if err := c.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
			t.Errorf("journal_mode = %q, %v; want wal", mode, err)
		}
		var timeout, fk, syn int
		if err := c.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != 5000 {
			t.Errorf("busy_timeout = %d, %v; want 5000", timeout, err)
		}
		if err := c.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
			t.Errorf("foreign_keys = %d, %v; want 1", fk, err)
		}
		if err := c.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&syn); err != nil || syn != 1 {
			t.Errorf("synchronous = %d, %v; want 1 (NORMAL)", syn, err)
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

func TestCreateGetRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()

	// Sub-millisecond parts must be dropped, local zones must come back as UTC.
	loc := time.FixedZone("X", 3*3600)
	created := time.Date(2026, 5, 1, 12, 0, 0, 123_456_789, loc)
	exp := created.Add(24 * time.Hour)
	used := created.Add(time.Hour)
	tok := newTok("aaaaaaaaaaaa", "home", created)
	tok.ExpiresAt = &exp
	tok.LastUsedAt = &used
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	got, err := s.GetToken(ctx, "aaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", got.CreatedAt.Location())
	}
	if want := created.Truncate(time.Millisecond); !got.CreatedAt.Equal(want) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, want)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp.Truncate(time.Millisecond)) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, exp.Truncate(time.Millisecond))
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(used.Truncate(time.Millisecond)) {
		t.Errorf("LastUsedAt = %v", got.LastUsedAt)
	}
	if got.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil", got.RevokedAt)
	}
	if got.Name != "home" || got.Last4 != "abcd" || got.MaxTunnels != 5 ||
		!reflect.DeepEqual(got.Scopes, tok.Scopes) || !reflect.DeepEqual(got.SecretHash, tok.SecretHash) {
		t.Errorf("fields mismatch: %+v", got)
	}
}

func TestCreateEmptyScopesAndNullTimes(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	tok := newTok("bbbbbbbbbbbb", "nul", time.Now())
	tok.Scopes = nil
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	got, err := s.GetToken(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Scopes) != 0 || got.ExpiresAt != nil || got.RevokedAt != nil || got.LastUsedAt != nil {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestCreateValidation(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	now := time.Now()
	tests := []struct {
		name string
		tok  *Token
	}{
		{"nil", nil},
		{"empty id", newTok("", "x", now)},
		{"empty name", newTok("cccccccccccc", "", now)},
		{"no hash", &Token{ID: "cccccccccccc", Name: "x"}},
		{"comma in scope", func() *Token { t := newTok("cccccccccccc", "x", now); t.Scopes = []string{"a,b"}; return t }()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.CreateToken(ctx, tc.tok); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestGetNotFound(t *testing.T) {
	s, _ := openTemp(t)
	if _, err := s.GetToken(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDuplicateIDIsNotNameTaken(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, newTok("dddddddddddd", "one", time.Now())); err != nil {
		t.Fatal(err)
	}
	err := s.CreateToken(ctx, newTok("dddddddddddd", "two", time.Now()))
	if err == nil || errors.Is(err, ErrNameTaken) {
		t.Errorf("err = %v, want non-ErrNameTaken error", err)
	}
}

func TestListOrderAndIncludesRevoked(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Insert out of creation order.
	for _, tc := range []struct {
		id string
		d  time.Duration
	}{{"cccccccccccc", 2 * time.Hour}, {"aaaaaaaaaaaa", 0}, {"bbbbbbbbbbbb", time.Hour}} {
		if err := s.CreateToken(ctx, newTok(tc.id, "n-"+tc.id[:1], base.Add(tc.d))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RevokeToken(ctx, "bbbbbbbbbbbb", base.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, tk := range list {
		ids = append(ids, tk.ID)
	}
	want := []string{"aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("ids = %v, want %v", ids, want)
	}
	if list[1].RevokedAt == nil {
		t.Error("revoked token not marked in list")
	}
}

func TestNameUniquenessAndReuseAfterRevoke(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	now := time.Now()

	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "home", now)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, newTok("bbbbbbbbbbbb", "home", now)); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate active name: err = %v, want ErrNameTaken", err)
	}
	if err := s.RevokeToken(ctx, "home", now); err != nil {
		t.Fatalf("revoke by name: %v", err)
	}
	if err := s.CreateToken(ctx, newTok("bbbbbbbbbbbb", "home", now)); err != nil {
		t.Fatalf("reuse after revoke: %v", err)
	}
	// Two revoked tokens may share a name too.
	if err := s.RevokeToken(ctx, "bbbbbbbbbbbb", now); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, newTok("cccccccccccc", "home", now)); err != nil {
		t.Fatalf("third token: %v", err)
	}
	list, err := s.ListTokens(ctx)
	if err != nil || len(list) != 3 {
		t.Fatalf("list = %d tokens, %v; want 3", len(list), err)
	}
}

func TestRevoke(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	later := now.Add(time.Hour)

	tests := []struct {
		name string
		do   func(t *testing.T, s *SQLite)
	}{
		{"by id", func(t *testing.T, s *SQLite) {
			if err := s.RevokeToken(context.Background(), "aaaaaaaaaaaa", later); err != nil {
				t.Fatal(err)
			}
			expectRevokedAt(t, s, "aaaaaaaaaaaa", &later)
			expectRevokedAt(t, s, "bbbbbbbbbbbb", nil)
		}},
		{"by name", func(t *testing.T, s *SQLite) {
			if err := s.RevokeToken(context.Background(), "office", later); err != nil {
				t.Fatal(err)
			}
			expectRevokedAt(t, s, "bbbbbbbbbbbb", &later)
			expectRevokedAt(t, s, "aaaaaaaaaaaa", nil)
		}},
		{"idempotent by id keeps first time", func(t *testing.T, s *SQLite) {
			ctx := context.Background()
			if err := s.RevokeToken(ctx, "aaaaaaaaaaaa", later); err != nil {
				t.Fatal(err)
			}
			if err := s.RevokeToken(ctx, "aaaaaaaaaaaa", later.Add(time.Hour)); err != nil {
				t.Fatalf("second revoke: %v", err)
			}
			expectRevokedAt(t, s, "aaaaaaaaaaaa", &later)
		}},
		{"revoked name is not found by name", func(t *testing.T, s *SQLite) {
			ctx := context.Background()
			if err := s.RevokeToken(ctx, "home", later); err != nil {
				t.Fatal(err)
			}
			if err := s.RevokeToken(ctx, "home", later); !errors.Is(err, ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		}},
		{"unknown", func(t *testing.T, s *SQLite) {
			if err := s.RevokeToken(context.Background(), "ghost", later); !errors.Is(err, ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		}},
		{"id wins over name", func(t *testing.T, s *SQLite) {
			// A token named like another token's id: the id match is used.
			ctx := context.Background()
			if err := s.CreateToken(ctx, newTok("cccccccccccc", "aaaaaaaaaaaa", now)); err != nil {
				t.Fatal(err)
			}
			if err := s.RevokeToken(ctx, "aaaaaaaaaaaa", later); err != nil {
				t.Fatal(err)
			}
			expectRevokedAt(t, s, "aaaaaaaaaaaa", &later)
			expectRevokedAt(t, s, "cccccccccccc", nil)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := openTemp(t)
			ctx := context.Background()
			for _, tk := range []*Token{newTok("aaaaaaaaaaaa", "home", now), newTok("bbbbbbbbbbbb", "office", now)} {
				if err := s.CreateToken(ctx, tk); err != nil {
					t.Fatal(err)
				}
			}
			tc.do(t, s)
		})
	}
}

func expectRevokedAt(t *testing.T, s *SQLite, id string, want *time.Time) {
	t.Helper()
	got, err := s.GetToken(context.Background(), id)
	if err != nil {
		t.Fatalf("GetToken(%s): %v", id, err)
	}
	switch {
	case want == nil && got.RevokedAt != nil:
		t.Errorf("%s: RevokedAt = %v, want nil", id, got.RevokedAt)
	case want != nil && (got.RevokedAt == nil || !got.RevokedAt.Equal(*want)):
		t.Errorf("%s: RevokedAt = %v, want %v", id, got.RevokedAt, want)
	}
}

func TestUsable(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	mk := func(id, name string, exp *time.Time) {
		tk := newTok(id, name, now.Add(-24*time.Hour))
		tk.ExpiresAt = exp
		if err := s.CreateToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	mk("aaaaaaaaaaaa", "forever", nil)
	mk("bbbbbbbbbbbb", "valid", &future)
	mk("cccccccccccc", "expired", &past)
	mk("dddddddddddd", "revoked", nil)
	if err := s.RevokeToken(ctx, "dddddddddddd", past); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		id   string
		want error
	}{
		{"aaaaaaaaaaaa", nil},
		{"bbbbbbbbbbbb", nil},
		{"cccccccccccc", ErrExpired},
		{"dddddddddddd", ErrRevoked},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			tk, err := s.GetToken(ctx, tc.id)
			if err != nil {
				t.Fatal(err)
			}
			if got := tk.Usable(now); !errors.Is(got, tc.want) {
				t.Errorf("Usable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTouch(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "home", time.Now())); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 7, 7, 7, 7, 7, 7_000_000, time.UTC)
	if err := s.TouchToken(ctx, "aaaaaaaaaaaa", at); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetToken(ctx, "aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(at) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, at)
	}
	if err := s.TouchToken(ctx, "unknown", at); !errors.Is(err, ErrNotFound) {
		t.Errorf("touch unknown: err = %v, want ErrNotFound", err)
	}
}

func TestTwoHandlesSameFile(t *testing.T) {
	a, path := openTemp(t)
	ctx := context.Background()
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	now := time.Now()
	if err := a.CreateToken(ctx, newTok("aaaaaaaaaaaa", "home", now)); err != nil {
		t.Fatal(err)
	}
	got, err := b.GetToken(ctx, "aaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("write by a not visible in b: %v", err)
	}
	if got.Name != "home" {
		t.Errorf("name = %q", got.Name)
	}

	// The CLI (b) revokes while the server (a) reads.
	if err := b.RevokeToken(ctx, "home", now); err != nil {
		t.Fatal(err)
	}
	got, err = a.GetToken(ctx, "aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Usable(now.Add(time.Second)); !errors.Is(err, ErrRevoked) {
		t.Errorf("Usable = %v, want ErrRevoked", err)
	}
	// Name uniqueness is enforced across handles.
	if err := b.CreateToken(ctx, newTok("bbbbbbbbbbbb", "home", now)); err != nil {
		t.Fatalf("reuse after revoke via other handle: %v", err)
	}
	if err := a.CreateToken(ctx, newTok("cccccccccccc", "home", now)); !errors.Is(err, ErrNameTaken) {
		t.Errorf("err = %v, want ErrNameTaken", err)
	}
}

func TestConcurrentTouchNoBusy(t *testing.T) {
	a, path := openTemp(t)
	ctx := context.Background()
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	const tokens = 4
	for i := range tokens {
		if err := a.CreateToken(ctx, newTok(fmt.Sprintf("tok%09d", i), fmt.Sprintf("c%d", i), time.Now())); err != nil {
			t.Fatal(err)
		}
	}

	const workers, iters = 8, 50
	errs := make(chan error, workers*iters)
	var wg sync.WaitGroup
	for w := range workers {
		s := a
		if w%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range iters {
				id := fmt.Sprintf("tok%09d", (w+i)%tokens)
				if err := s.TouchToken(ctx, id, time.Now()); err != nil {
					errs <- err
				}
				if i%10 == 0 {
					// Mix in a revoke-style transaction on an unknown name.
					if err := s.RevokeToken(ctx, "ghost", time.Now()); !errors.Is(err, ErrNotFound) {
						errs <- fmt.Errorf("revoke ghost: %w", err)
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent op: %v", err)
	}
}

func TestReopenKeepsDataAndMigrations(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "home", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		s2, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		if _, err := s2.GetToken(ctx, "aaaaaaaaaaaa"); err != nil {
			t.Errorf("token lost after reopen: %v", err)
		}
		var n int
		if err := s2.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != len(testMigrations(t)) {
			t.Errorf("schema_migrations rows = %d, %v; want one per migration", n, err)
		}
		_ = s2.Close()
	}
}

func TestConcurrentFirstOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	ctx := context.Background()
	const n = 6
	var wg sync.WaitGroup
	stores := make([]*SQLite, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stores[i], errs[i] = Open(ctx, path)
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Errorf("Open #%d: %v", i, errs[i])
			continue
		}
		t.Cleanup(func() { _ = stores[i].Close() })
	}
	if errs[0] == nil {
		var cnt int
		if err := stores[0].db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&cnt); err != nil || cnt != len(testMigrations(t)) {
			t.Errorf("schema_migrations rows = %d, %v; want one per migration", cnt, err)
		}
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (999, 0)`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s2, err := Open(ctx, path); err == nil {
		_ = s2.Close()
		t.Error("Open succeeded on a database from a newer version")
	}
}

func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, ""); err == nil {
		t.Error("empty path: want error")
	}
	// Parent is a file, so MkdirAll fails.
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, filepath.Join(f, "sub", "db")); err == nil {
		t.Error("path under a regular file: want error")
	}
}

func testMigrations(t *testing.T) []migration {
	t.Helper()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func TestLoadMigrations(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 || ms[0].version != 1 {
		t.Fatalf("migrations = %+v", ms)
	}
}
