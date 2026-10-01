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
func (s *SQLite) ClaimLabels(ctx context.Context, client, tunnel string, labels []string, at time.Time) ([]string, error) {
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
		res, err := tx.ExecContext(ctx,
			`INSERT INTO label_claims (label, client, tunnel, claimed_at) VALUES (?, ?, ?, ?) ON CONFLICT (label) DO NOTHING`,
			l, client, tunnel, at.UnixMilli())
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
