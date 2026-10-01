// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	defaultAuditLimit = 100
	maxAuditLimit     = 1000
	maxAuditArgsLen   = 4096

	// DefaultAuditMaxRows is how many audit rows are kept unless SetAuditMaxRows says otherwise.
	DefaultAuditMaxRows = 100_000
	// auditPruneEvery is how many appends pass between two retention sweeps.
	auditPruneEvery = 64
	// deniedWindow is how often one actor may add a "denied" row; repeats inside it are counted, not stored.
	deniedWindow = time.Minute
	// maxDeniedActors bounds the memory of the denied rate limiter.
	maxDeniedActors = 4096
)

// auditState holds the retention setting and the denied-entry rate limiter. The zero value keeps DefaultAuditMaxRows.
type auditState struct {
	mu      sync.Mutex
	maxRows int
	appends int
	denied  map[string]*deniedState
}

type deniedState struct {
	since      time.Time
	suppressed int
}

// SetAuditMaxRows sets how many audit rows to keep (the oldest are deleted); n <= 0 keeps DefaultAuditMaxRows.
func (s *SQLite) SetAuditMaxRows(n int) {
	s.audit.mu.Lock()
	s.audit.maxRows = n
	s.audit.mu.Unlock()
}

// admitDenied decides whether a "denied" entry of actor at time at is stored. Of a burst only the first entry per
// window is; the entry that opens the next window reports how many were dropped in between (second result).
func (a *auditState) admitDenied(actor string, at time.Time) (store bool, suppressed int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.denied == nil {
		a.denied = make(map[string]*deniedState)
	}
	st := a.denied[actor]
	if st != nil && at.Sub(st.since) < deniedWindow && !at.Before(st.since) {
		st.suppressed++
		return false, 0
	}
	if st == nil {
		if len(a.denied) >= maxDeniedActors {
			for k, v := range a.denied {
				if at.Sub(v.since) >= deniedWindow {
					delete(a.denied, k)
				}
			}
		}
		st = &deniedState{}
		a.denied[actor] = st
	}
	suppressed = st.suppressed
	st.since, st.suppressed = at, 0
	return true, suppressed
}

// withSuppressed adds {"suppressed": n} to a JSON object, or wraps a non-object text.
func withSuppressed(args string, n int) string {
	m := map[string]any{}
	if args != "" {
		if err := json.Unmarshal([]byte(args), &m); err != nil || m == nil {
			m = map[string]any{"args": args}
		}
	}
	m["suppressed"] = n
	b, _ := json.Marshal(m)
	return string(b)
}

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

// AppendAudit implements Store. Over-long fields are truncated, never rejected: losing a record is worse. The one
// exception is a flood of "denied" entries from one actor (any authenticated token can make them at will): only the
// first per minute is stored, the next one says how many were dropped ("suppressed" in args), and the dropped ones get
// ID 0. The log keeps at most the newest SetAuditMaxRows rows.
func (s *SQLite) AppendAudit(ctx context.Context, e *AuditEntry) error {
	if e.Result == "denied" {
		store, suppressed := s.audit.admitDenied(e.Actor, e.At)
		if !store {
			e.ID = 0
			return nil
		}
		if suppressed > 0 {
			c := *e
			c.Args = withSuppressed(e.Args, suppressed)
			e = &c
		}
	}
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
	s.pruneAudit(ctx)
	return nil
}

// pruneAudit deletes the oldest rows beyond the retention limit, every auditPruneEvery appends. Ids only grow
// (AUTOINCREMENT), so "newest N" is a range on the primary key. Failure is not an error of the append.
func (s *SQLite) pruneAudit(ctx context.Context) {
	s.audit.mu.Lock()
	s.audit.appends++
	run := s.audit.appends%auditPruneEvery == 1
	keep := s.audit.maxRows
	s.audit.mu.Unlock()
	if !run {
		return
	}
	if keep <= 0 {
		keep = DefaultAuditMaxRows
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE id <= (SELECT MAX(id) FROM audit_log) - ?`, keep)
}

// ListAudit implements Store. A limit <= 0 means 100; it is capped at 1000.
func (s *SQLite) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	return s.ListAuditBefore(ctx, 0, limit)
}

// AuditPager is implemented by stores that can page through the audit log.
type AuditPager interface {
	// ListAuditBefore is ListAudit for the entries with an id below before; before <= 0 starts at the newest.
	ListAuditBefore(ctx context.Context, before int64, limit int) ([]AuditEntry, error)
}

// TokenCascader is implemented by stores that can revoke a token together with the tokens its join links minted.
type TokenCascader interface {
	// RevokeTokenCascade returns the id of the target (first) and of the tokens it revoked below it.
	RevokeTokenCascade(ctx context.Context, idOrName string, at time.Time) ([]string, error)
}

var (
	_ AuditPager    = (*SQLite)(nil)
	_ TokenCascader = (*SQLite)(nil)
)

// ListAuditBefore implements AuditPager.
func (s *SQLite) ListAuditBefore(ctx context.Context, before int64, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	limit = min(limit, maxAuditLimit)
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, actor, action, target, args, result FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?`, before, limit)
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
