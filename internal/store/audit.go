// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"
)

const (
	defaultAuditLimit = 100
	maxAuditLimit     = 1000
	maxAuditArgsLen   = 4096
)

// AuditEntry is one record of the append-only admin audit log.
type AuditEntry struct {
	ID     int64 // assigned by AppendAudit
	At     time.Time
	Actor  string // token id, or "socket" for the local admin socket
	Action string // e.g. "client.disconnect"
	Target string // e.g. the client name or tunnel id
	Args   string // JSON object; must not contain secrets
	Result string // "ok", "denied" or "error: <code>"
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// AppendAudit implements Store. Over-long fields are truncated, never rejected: losing a record is worse.
func (s *SQLite) AppendAudit(ctx context.Context, e *AuditEntry) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (at, actor, action, target, args, result) VALUES (?, ?, ?, ?, ?, ?)`,
		e.At.UnixMilli(), truncate(e.Actor, maxFieldLen), truncate(e.Action, maxFieldLen),
		truncate(e.Target, maxFieldLen), truncate(e.Args, maxAuditArgsLen), truncate(e.Result, maxFieldLen))
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	if id, err := res.LastInsertId(); err == nil {
		e.ID = id
	}
	return nil
}

// ListAudit implements Store. A limit <= 0 means 100; it is capped at 1000.
func (s *SQLite) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	limit = min(limit, maxAuditLimit)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, actor, action, target, args, result FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Args, &e.Result); err != nil {
			return nil, fmt.Errorf("store: list audit: %w", err)
		}
		e.At = timeFromMS(at)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	return out, nil
}
