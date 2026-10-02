// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// maxClaimLabels bounds one ClaimLabels call; a tunnel claims at most its label and, for ssh, the bare client name.
const maxClaimLabels = 8

// queryRower is the part of *sql.DB and *sql.Tx that checkNameNotClaimed needs.
type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ClaimLabels implements Store.
func (s *SQLite) ClaimLabels(ctx context.Context, client, tunnel string, labels []string, at time.Time, maxClaims int) ([]string, error) {
	if client == "" || tunnel == "" || len(labels) == 0 || len(labels) > maxClaimLabels {
		return nil, errors.New("store: label claim needs a client, a tunnel and a few labels")
	}
	if len(client) > maxFieldLen || len(tunnel) > maxFieldLen {
		return nil, errors.New("store: label claim field too long")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: claim labels: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var created []string
	for _, l := range labels {
		if l == "" || len(l) > maxFieldLen {
			return nil, errors.New("store: label claim: bad label")
		}
		// The bare name of every client belongs to it from the moment its token exists; only the client itself may
		// compose it (the symmetric half of checkNameNotClaimed).
		if l != client {
			if err := checkNotAClientName(ctx, tx, l); err != nil {
				return nil, err
			}
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO label_claims (label, client, tunnel, claimed_at, last_used_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (label) DO NOTHING`,
			l, client, tunnel, at.UnixMilli(), at.UnixMilli())
		if err != nil {
			return nil, fmt.Errorf("store: claim labels: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("store: claim labels: %w", err)
		}
		if n == 1 {
			created = append(created, l)
			continue
		}
		var c, t string
		if err := tx.QueryRowContext(ctx, `SELECT client, tunnel FROM label_claims WHERE label = ?`, l).Scan(&c, &t); err != nil {
			return nil, fmt.Errorf("store: claim labels: %w", err)
		}
		if c != client || t != tunnel {
			return nil, fmt.Errorf("label %q: %w", l, ErrLabelClaimed)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE label_claims SET last_used_at = ? WHERE label = ?`, at.UnixMilli(), l); err != nil {
			return nil, fmt.Errorf("store: claim labels: %w", err)
		}
	}
	if maxClaims > 0 && len(created) > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM label_claims WHERE client = ?`, client).Scan(&n); err != nil {
			return nil, fmt.Errorf("store: claim labels: %w", err)
		}
		if n > maxClaims {
			return nil, fmt.Errorf("client %q already holds %d permanent names, the limit is %d: %w",
				client, n-len(created), maxClaims, ErrLabelLimit)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: claim labels: %w", err)
	}
	return created, nil
}

// UnclaimLabels implements Store.
func (s *SQLite) UnclaimLabels(ctx context.Context, client, tunnel string, labels []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: unclaim labels: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, l := range labels {
		if _, err := tx.ExecContext(ctx, `DELETE FROM label_claims WHERE label = ? AND client = ? AND tunnel = ?`,
			l, client, tunnel); err != nil {
			return fmt.Errorf("store: unclaim labels: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: unclaim labels: %w", err)
	}
	return nil
}

// ReleaseLabel implements Store.
func (s *SQLite) ReleaseLabel(ctx context.Context, label string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM label_claims WHERE label = ?`, label)
	if err != nil {
		return fmt.Errorf("store: release label: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: release label: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("label %q: %w", label, ErrNotFound)
	}
	return nil
}

// checkNameNotClaimed fails with ErrNameTaken when name, as a client name, would be the bare SSH address of a
// client while the same string is already the permanent label of another client's tunnel: the SSH gateway resolves
// both from one namespace (ADR 0003). Creating the token would only move the failure to the first ssh registration.
func checkNameNotClaimed(ctx context.Context, q queryRower, name string) error {
	var owner, tunnel string
	err := q.QueryRowContext(ctx, `SELECT client, tunnel FROM label_claims WHERE label = ? AND client <> ?`, name, name).
		Scan(&owner, &tunnel)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: check name: %w", err)
	}
	return fmt.Errorf("client name %q is already the hostname label of another client's tunnel "+
		"(release it with `portholed admin release-label %s` or pick another name): %w", name, name, ErrNameTaken)
}

// checkNotAClientName fails with ErrLabelClaimed when label is the name of an active token: the bare SSH address of
// that client, which no other client may compose as "<tunnel>-<client>". The reservation is derived from the tokens
// table, so it exists from the moment of CreateToken or the redemption of a join code, covers the tokens that
// predate it and ends with the revocation of the token.
func checkNotAClientName(ctx context.Context, q queryRower, label string) error {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens WHERE name = ? AND revoked_at IS NULL`, label).Scan(&n); err != nil {
		return fmt.Errorf("store: claim labels: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("label %q is the name of another client: %w", label, ErrLabelClaimed)
	}
	return nil
}

// ExpireLabelClaims implements Store.
func (s *SQLite) ExpireLabelClaims(ctx context.Context, now time.Time, ttl time.Duration, live []ClaimOwner) (int, error) {
	if ttl <= 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: expire labels: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, o := range live {
		if _, err := tx.ExecContext(ctx, `UPDATE label_claims SET last_used_at = ? WHERE client = ? AND tunnel = ?`,
			now.UnixMilli(), o.Client, o.Tunnel); err != nil {
			return 0, fmt.Errorf("store: expire labels: %w", err)
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM label_claims WHERE COALESCE(last_used_at, claimed_at) < ?`,
		now.Add(-ttl).UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("store: expire labels: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: expire labels: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: expire labels: %w", err)
	}
	return int(n), nil
}
