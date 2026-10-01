// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
)

// newJoin stores a join code valid for 15 minutes from t0 and returns it with its secret.
func newJoin(t *testing.T, s *SQLite, name string, mut ...func(*JoinCode)) (*JoinCode, auth.Token) {
	t.Helper()
	code, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	jc := &JoinCode{
		ID: code.ID, CodeHash: code.Hash(), ClientName: name, Scopes: []string{"tunnel:http", "tunnel:tcp"},
		MaxTunnels: 3, RemoteControl: true, CreatedAt: t0, ExpiresAt: t0.Add(DefaultJoinTTL), CreatedBy: "socket",
	}
	for _, m := range mut {
		m(jc)
	}
	if err := s.CreateJoinCode(context.Background(), jc); err != nil {
		t.Fatalf("CreateJoinCode: %v", err)
	}
	return jc, code
}

func TestRedeemCreatesTokenOnce(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	exp := t0.Add(30 * 24 * time.Hour)
	jc, code := newJoin(t, s, "home", func(j *JoinCode) { j.TokenExpiresAt = &exp })

	now := t0.Add(time.Minute)
	tok, raw, err := s.RedeemJoinCode(ctx, jc.ID, code.Secret, now)
	if err != nil {
		t.Fatalf("RedeemJoinCode: %v", err)
	}
	parsed, err := auth.Parse(raw)
	if err != nil || parsed.ID != tok.ID || !auth.Verify(parsed.Secret, tok.SecretHash) {
		t.Fatalf("raw token %q does not match the stored token (%v)", raw, err)
	}
	got, err := s.GetToken(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "home" || got.MaxTunnels != 3 || !got.RemoteControl || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) ||
		len(got.Scopes) != 2 || !got.CreatedAt.Equal(now) {
		t.Errorf("stored token = %+v", got)
	}

	if _, _, err := s.RedeemJoinCode(ctx, jc.ID, code.Secret, now); !errors.Is(err, ErrJoinUsed) {
		t.Errorf("second redemption: err = %v, want ErrJoinUsed", err)
	}
	codes, _ := s.ListJoinCodes(ctx)
	if len(codes) != 1 || codes[0].UsedAt == nil || codes[0].Status(now) != "used" {
		t.Errorf("list after use = %+v", codes)
	}
	toks, _ := s.ListTokens(ctx)
	if len(toks) != 1 {
		t.Errorf("tokens = %d, want 1", len(toks))
	}
}

func TestRedeemWithoutRemoteControl(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	jc, code := newJoin(t, s, "home", func(j *JoinCode) { j.RemoteControl = false })
	tok, _, err := s.RedeemJoinCode(ctx, jc.ID, code.Secret, t0)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetToken(ctx, tok.ID); got.RemoteControl {
		t.Error("remote_control leaked in from the column default")
	}
}

func TestRedeemRefusals(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	jc, code := newJoin(t, s, "home")

	if _, _, err := s.RedeemJoinCode(ctx, jc.ID, "wrongsecret", t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong secret: %v, want ErrNotFound", err)
	}
	if _, _, err := s.RedeemJoinCode(ctx, "unknownidxxxx", code.Secret, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v, want ErrNotFound", err)
	}
	if _, _, err := s.RedeemJoinCode(ctx, jc.ID, code.Secret, t0.Add(DefaultJoinTTL)); !errors.Is(err, ErrJoinExpired) {
		t.Errorf("at expiry: %v, want ErrJoinExpired", err)
	}
	// Nothing was spent by the refusals: the code still works inside its lifetime.
	if _, _, err := s.RedeemJoinCode(ctx, jc.ID, code.Secret, t0.Add(DefaultJoinTTL-time.Second)); err != nil {
		t.Errorf("redeem just before expiry: %v", err)
	}
}

func TestRedeemTokenWouldBeExpired(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	exp := t0.Add(time.Minute)
	jc, code := newJoin(t, s, "home", func(j *JoinCode) { j.TokenExpiresAt = &exp })
	if _, _, err := s.RedeemJoinCode(ctx, jc.ID, code.Secret, t0.Add(2*time.Minute)); !errors.Is(err, ErrJoinExpired) {
		t.Errorf("err = %v, want ErrJoinExpired", err)
	}
}

func TestRevokeJoinCode(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	jc, code := newJoin(t, s, "home")
	if err := s.RevokeJoinCode(ctx, jc.ID, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeJoinCode(ctx, jc.ID, t0.Add(time.Second)); err != nil {
		t.Errorf("second revoke: %v (want idempotent)", err)
	}
	if err := s.RevokeJoinCode(ctx, "unknownidxxxx", t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v, want ErrNotFound", err)
	}
	if _, _, err := s.RedeemJoinCode(ctx, jc.ID, code.Secret, t0); !errors.Is(err, ErrJoinRevoked) {
		t.Errorf("redeem revoked: %v, want ErrJoinRevoked", err)
	}
	codes, _ := s.ListJoinCodes(ctx)
	if len(codes) != 1 || codes[0].Status(t0) != "revoked" || !codes[0].RevokedAt.Equal(t0) {
		t.Errorf("list = %+v", codes)
	}

	// A used code cannot be revoked after the fact: it stays "used".
	jc2, code2 := newJoin(t, s, "work")
	if _, _, err := s.RedeemJoinCode(ctx, jc2.ID, code2.Secret, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeJoinCode(ctx, jc2.ID, t0); err != nil {
		t.Fatal(err)
	}
	codes, _ = s.ListJoinCodes(ctx)
	byID := map[string]*JoinCode{}
	for _, c := range codes {
		byID[c.ID] = c
	}
	if u := byID[jc2.ID]; u.Status(t0) != "used" || u.RevokedAt != nil {
		t.Errorf("used code after revoke = %+v", u)
	}
}

func TestJoinNameTaken(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.CreateToken(ctx, newTok("aaaaaaaaaaaa", "home", t0)); err != nil {
		t.Fatal(err)
	}
	code, _ := auth.Generate()
	jc := &JoinCode{ID: code.ID, CodeHash: code.Hash(), ClientName: "home", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
	if err := s.CreateJoinCode(ctx, jc); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("create for a taken name: %v, want ErrNameTaken", err)
	}

	// A name that was free at creation but taken by redemption time: the code is not spent.
	jc2, code2 := newJoin(t, s, "work")
	if err := s.CreateToken(ctx, newTok("bbbbbbbbbbbb", "work", t0)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemJoinCode(ctx, jc2.ID, code2.Secret, t0); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("redeem: %v, want ErrNameTaken", err)
	}
	if err := s.RevokeToken(ctx, "bbbbbbbbbbbb", t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemJoinCode(ctx, jc2.ID, code2.Secret, t0); err != nil {
		t.Errorf("redeem after the name was freed: %v", err)
	}
}

func TestRedeemConcurrentExactlyOne(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	s2, err := Open(ctx, path) // a second handle on the same file, as a second process would be
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	jc, code := newJoin(t, s, "home")

	const n = 16
	var (
		wg    sync.WaitGroup
		ok    atomic.Int32
		used  atomic.Int32
		other atomic.Int32
	)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := s
			if i%2 == 1 {
				h = s2
			}
			<-start
			_, _, err := h.RedeemJoinCode(ctx, jc.ID, code.Secret, t0)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrJoinUsed):
				used.Add(1)
			default:
				other.Add(1)
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != 1 || used.Load() != n-1 {
		t.Fatalf("successes = %d, used = %d, other = %d; want 1, %d, 0", ok.Load(), used.Load(), other.Load(), n-1)
	}
	if toks, _ := s.ListTokens(ctx); len(toks) != 1 {
		t.Errorf("%d tokens created, want 1", len(toks))
	}
}

func TestCreateJoinCodeValidation(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for name, jc := range map[string]*JoinCode{
		"nil":         nil,
		"no id":       {ClientName: "a", CodeHash: []byte("x")},
		"no name":     {ID: "a", CodeHash: []byte("x")},
		"no hash":     {ID: "a", ClientName: "a"},
		"bad scope":   {ID: "a", ClientName: "a", CodeHash: []byte("x"), Scopes: []string{"a,b"}},
		"empty scope": {ID: "a", ClientName: "a", CodeHash: []byte("x"), Scopes: []string{""}},
	} {
		if err := s.CreateJoinCode(ctx, jc); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// A database made by the previous release (migrations up to 0003) opens, gains the join table, and its tokens keep
// remote_control = 1.
func TestMigrationFrom0003(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	for _, q := range []string{
		`DROP TABLE join_codes`,
		`DROP TABLE label_claims`,
		`ALTER TABLE tokens DROP COLUMN remote_control`,
		`DROP INDEX tokens_created_by`,
		`ALTER TABLE tokens DROP COLUMN created_by`,
		`DELETE FROM schema_migrations WHERE version >= 4`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, name, secret_hash, last4, scopes, max_tunnels, created_at) VALUES ('aaaaaaaaaaaa', 'old', x'01', 'abcd', 'tunnel:http', 0, 1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open 0003 database: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	old, err := s2.GetToken(ctx, "aaaaaaaaaaaa")
	if err != nil || !old.RemoteControl {
		t.Fatalf("old token = %+v, %v; want RemoteControl true", old, err)
	}
	jc, code := newJoin(t, s2, "home")
	if _, _, err := s2.RedeemJoinCode(ctx, jc.ID, code.Secret, t0); err != nil {
		t.Errorf("redeem after migration: %v", err)
	}
}
