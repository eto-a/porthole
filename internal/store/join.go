// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eto-a/porthole/internal/auth"
)

// DefaultJoinTTL is how long a join code lives when the creator does not say (ADR 0005).
const DefaultJoinTTL = 15 * time.Minute

// JoinCode is a one-time enrolment: whoever presents the secret receives a permanent token with the stated name and
// scopes. Only a hash of the secret is stored.
type JoinCode struct {
	ID             string // public part of pj_<id>_<secret>
	CodeHash       []byte // sha256(secret)
	ClientName     string // name of the token the redemption creates
	Scopes         []string
	MaxTunnels     int        // 0 = server default
	TokenExpiresAt *time.Time // absolute expiry of the created token; nil = never
	RemoteControl  bool       // the created token's machine accepts remotely opened tunnels
	CreatedAt      time.Time
	ExpiresAt      time.Time  // the code cannot be redeemed at or after this time
	UsedAt         *time.Time // nil = not redeemed
	RevokedAt      *time.Time // nil = not revoked
	CreatedBy      string     // token id of the creator, or "socket"
}

// Status describes the code at now: "active", "used", "revoked" or "expired".
func (j *JoinCode) Status(now time.Time) string {
	switch {
	case j.UsedAt != nil:
		return "used"
	case j.RevokedAt != nil:
		return "revoked"
	case !now.Before(j.ExpiresAt):
		return "expired"
	}
	return "active"
}

const joinColumns = `id, code_hash, client_name, scopes, max_tunnels, token_expires_at, remote_control, created_at, expires_at, used_at, revoked_at, created_by`

func scanJoin(sc scanner) (*JoinCode, error) {
	var (
		j                     JoinCode
		scopes                string
		tokExp, used, revoked sql.NullInt64
		created, expires      int64
	)
	if err := sc.Scan(&j.ID, &j.CodeHash, &j.ClientName, &scopes, &j.MaxTunnels, &tokExp, &j.RemoteControl,
		&created, &expires, &used, &revoked, &j.CreatedBy); err != nil {
		return nil, err
	}
	if scopes != "" {
		j.Scopes = strings.Split(scopes, ",")
	}
	j.TokenExpiresAt = ptrTime(tokExp)
	j.CreatedAt = timeFromMS(created)
	j.ExpiresAt = timeFromMS(expires)
	j.UsedAt = ptrTime(used)
	j.RevokedAt = ptrTime(revoked)
	return &j, nil
}

// CreateJoinCode implements Store.
func (s *SQLite) CreateJoinCode(ctx context.Context, jc *JoinCode) error {
	if jc == nil || jc.ID == "" || jc.ClientName == "" || len(jc.CodeHash) == 0 {
		return errors.New("store: join code needs id, client name and hash")
	}
	if len(jc.ID) > maxFieldLen || len(jc.ClientName) > maxFieldLen || len(jc.CreatedBy) > maxFieldLen {
		return errors.New("store: join code field too long")
	}
	for _, sc := range jc.Scopes {
		if sc == "" || strings.Contains(sc, ",") {
			return fmt.Errorf("store: invalid scope %q", sc)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: create join code: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Fail early when the name is taken, instead of handing out a link that cannot be redeemed. Redeeming checks again.
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens WHERE name = ? AND revoked_at IS NULL`,
		jc.ClientName).Scan(&n); err != nil {
		return fmt.Errorf("store: create join code: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("token name %q: %w", jc.ClientName, ErrNameTaken)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO join_codes (`+joinColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jc.ID, jc.CodeHash, jc.ClientName, strings.Join(jc.Scopes, ","), jc.MaxTunnels, msOrNull(jc.TokenExpiresAt),
		jc.RemoteControl, jc.CreatedAt.UnixMilli(), jc.ExpiresAt.UnixMilli(), msOrNull(jc.UsedAt), msOrNull(jc.RevokedAt),
		jc.CreatedBy); err != nil {
		return fmt.Errorf("store: create join code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: create join code: %w", err)
	}
	return nil
}

// RedeemJoinCode implements Store. The whole redemption is one BEGIN IMMEDIATE transaction, so of any number of
// concurrent attempts (also from other processes) exactly one succeeds.
func (s *SQLite) RedeemJoinCode(ctx context.Context, id, secret string, now time.Time) (*Token, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("store: redeem join code: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	jc, err := scanJoin(tx.QueryRowContext(ctx, `SELECT `+joinColumns+` FROM join_codes WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		auth.Verify(secret, make([]byte, 32)) // keep the unknown-id path as slow as the wrong-secret path
		return nil, "", fmt.Errorf("join code %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, "", fmt.Errorf("store: redeem join code: %w", err)
	}
	if !auth.Verify(secret, jc.CodeHash) {
		return nil, "", fmt.Errorf("join code %q: %w", id, ErrNotFound)
	}
	switch {
	case jc.RevokedAt != nil:
		return nil, "", fmt.Errorf("join code %q: %w", id, ErrJoinRevoked)
	case jc.UsedAt != nil:
		return nil, "", fmt.Errorf("join code %q: %w", id, ErrJoinUsed)
	case !now.Before(jc.ExpiresAt):
		return nil, "", fmt.Errorf("join code %q: %w", id, ErrJoinExpired)
	case jc.TokenExpiresAt != nil && !now.Before(*jc.TokenExpiresAt):
		return nil, "", fmt.Errorf("join code %q: its token would already be expired: %w", id, ErrJoinExpired)
	}

	raw, err := auth.Generate()
	if err != nil {
		return nil, "", fmt.Errorf("store: redeem join code: %w", err)
	}
	tok := &Token{
		ID:            raw.ID,
		Name:          jc.ClientName,
		SecretHash:    raw.Hash(),
		Last4:         raw.Last4(),
		Scopes:        jc.Scopes,
		MaxTunnels:    jc.MaxTunnels,
		CreatedAt:     now,
		ExpiresAt:     jc.TokenExpiresAt,
		RemoteControl: jc.RemoteControl,
		CreatedBy:     jc.CreatedBy,
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tokens (id, name, secret_hash, last4, scopes, max_tunnels, created_at, expires_at, remote_control, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tok.ID, tok.Name, tok.SecretHash, tok.Last4, strings.Join(tok.Scopes, ","), tok.MaxTunnels,
		now.UnixMilli(), msOrNull(tok.ExpiresAt), tok.RemoteControl, tok.CreatedBy); err != nil {
		if isUniqueViolation(err) {
			return nil, "", fmt.Errorf("token name %q: %w", tok.Name, ErrNameTaken)
		}
		return nil, "", fmt.Errorf("store: redeem join code: create token: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE join_codes SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`,
		now.UnixMilli(), id)
	if err != nil {
		return nil, "", fmt.Errorf("store: redeem join code: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return nil, "", fmt.Errorf("join code %q: %w", id, ErrJoinUsed)
	}
	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("store: redeem join code: %w", err)
	}
	return tok, raw.String(), nil
}

// ListJoinCodes implements Store.
func (s *SQLite) ListJoinCodes(ctx context.Context) ([]*JoinCode, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+joinColumns+` FROM join_codes ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list join codes: %w", err)
	}
	defer rows.Close()
	var out []*JoinCode
	for rows.Next() {
		j, err := scanJoin(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list join codes: %w", err)
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list join codes: %w", err)
	}
	return out, nil
}

// RevokeJoinCode implements Store.
func (s *SQLite) RevokeJoinCode(ctx context.Context, id string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: revoke join code: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var found int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM join_codes WHERE id = ?`, id).Scan(&found); err != nil {
		return fmt.Errorf("store: revoke join code: %w", err)
	}
	if found == 0 {
		return fmt.Errorf("join code %q: %w", id, ErrNotFound)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE join_codes SET revoked_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`, at.UnixMilli(), id); err != nil {
		return fmt.Errorf("store: revoke join code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: revoke join code: %w", err)
	}
	return nil
}
