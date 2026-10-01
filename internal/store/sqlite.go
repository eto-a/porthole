// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const (
	// openAttempts bounds retries of Open when another process holds the database during
	// the initial journal_mode switch or migration (SQLITE_BUSY despite busy_timeout).
	openAttempts = 5
	openBackoff  = 100 * time.Millisecond

	// maxOpenConns bounds the connection pool.
	maxOpenConns = 8

	// maxFieldLen bounds the length of text fields.
	maxFieldLen = 1024
)

// SQLite is a Store backed by a SQLite database in WAL mode. It is safe for concurrent use and
// for use by several processes on the same file.
type SQLite struct {
	db *sql.DB
}

var _ Store = (*SQLite)(nil)

// Open opens (creating if needed) the database at path and applies pending migrations.
// The parent directory is created with mode 0700 and a new file with 0600 (effective on unix).
func Open(ctx context.Context, path string) (*SQLite, error) {
	if path == "" {
		return nil, errors.New("store: empty database path")
	}
	if err := prepareFile(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(maxOpenConns)

	var lastErr error
	for attempt := range openAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				_ = db.Close()
				return nil, fmt.Errorf("store: open %s: %w", path, ctx.Err())
			case <-time.After(openBackoff * time.Duration(attempt)):
			}
		}
		lastErr = db.PingContext(ctx)
		if lastErr == nil {
			lastErr = migrate(ctx, db)
		}
		if lastErr == nil {
			return &SQLite{db: db}, nil
		}
		if !isBusy(lastErr) {
			break
		}
	}
	_ = db.Close()
	return nil, fmt.Errorf("store: open %s: %w", path, lastErr)
}

// prepareFile creates the directory (0700) and an empty database file (0600) if they do not exist.
func prepareFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("store: create directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("store: create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: close database file: %w", err)
	}
	return nil
}

// dsn builds the driver DSN. Pragmas are passed as _pragma so the driver applies them on every
// new pooled connection. _txlock=immediate makes BeginTx issue BEGIN IMMEDIATE, so write
// transactions wait on busy_timeout instead of failing at the read-to-write lock upgrade.
func dsn(path string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	return path + "?" + q.Encode()
}

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads migrations/NNNN_name.sql from the embedded FS, ordered by version.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	var ms []migration
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q: want NNNN_name.sql", name)
		}
		v, err := strconv.Atoi(prefix)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %q: bad version prefix", name)
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+name)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}
		ms = append(ms, migration{version: v, name: name, sql: string(body)})
	}
	slices.SortFunc(ms, func(a, b migration) int { return a.version - b.version })
	for i := 1; i < len(ms); i++ {
		if ms[i].version == ms[i-1].version {
			return nil, fmt.Errorf("duplicate migration version %d", ms[i].version)
		}
	}
	return ms, nil
}

// migrate applies pending migrations in one BEGIN IMMEDIATE transaction. A second process doing
// the same blocks on busy_timeout, then finds everything already applied.
func migrate(ctx context.Context, db *sql.DB) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	applied := map[int]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}

	known := map[int]bool{}
	for _, m := range ms {
		known[m.version] = true
	}
	for v := range applied {
		if !known[v] {
			return fmt.Errorf("database schema version %d is newer than this binary supports", v)
		}
	}

	for _, m := range ms {
		if applied[m.version] {
			continue
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			m.version, time.Now().UnixMilli()); err != nil {
			return fmt.Errorf("record migration %s: %w", m.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}

// sqliteCode extracts the SQLite extended result code from err, if any.
func sqliteCode(err error) (int, bool) {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code(), true
	}
	return 0, false
}

// isBusy reports whether err is SQLITE_BUSY or SQLITE_LOCKED (including extended codes).
func isBusy(err error) bool {
	code, ok := sqliteCode(err)
	if !ok {
		return false
	}
	p := code & 0xff
	return p == sqlite3.SQLITE_BUSY || p == sqlite3.SQLITE_LOCKED
}

// isUniqueViolation reports whether err is a UNIQUE constraint failure.
func isUniqueViolation(err error) bool {
	code, ok := sqliteCode(err)
	return ok && code == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

func msOrNull(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixMilli()
}

func timeFromMS(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func ptrTime(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := timeFromMS(n.Int64)
	return &t
}

// CreateToken implements Store.
func (s *SQLite) CreateToken(ctx context.Context, t *Token) error {
	if t == nil || t.ID == "" || t.Name == "" || len(t.SecretHash) == 0 {
		return errors.New("store: token needs id, name and secret hash")
	}
	if len(t.ID) > maxFieldLen || len(t.Name) > maxFieldLen || len(t.Last4) > maxFieldLen {
		return errors.New("store: token field too long")
	}
	for _, sc := range t.Scopes {
		if sc == "" || strings.Contains(sc, ",") {
			return fmt.Errorf("store: invalid scope %q", sc)
		}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, name, secret_hash, last4, scopes, max_tunnels, created_at, expires_at, revoked_at, last_used_at, remote_control)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.SecretHash, t.Last4, strings.Join(t.Scopes, ","), t.MaxTunnels,
		t.CreatedAt.UnixMilli(), msOrNull(t.ExpiresAt), msOrNull(t.RevokedAt), msOrNull(t.LastUsedAt), t.RemoteControl)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("token name %q: %w", t.Name, ErrNameTaken)
		}
		return fmt.Errorf("store: create token: %w", err)
	}
	return nil
}

const tokenColumns = `id, name, secret_hash, last4, scopes, max_tunnels, created_at, expires_at, revoked_at, last_used_at, remote_control`

type scanner interface{ Scan(dest ...any) error }

func scanToken(sc scanner) (*Token, error) {
	var (
		t                    Token
		scopes               string
		created              int64
		expires, revoked, lu sql.NullInt64
	)
	if err := sc.Scan(&t.ID, &t.Name, &t.SecretHash, &t.Last4, &scopes, &t.MaxTunnels,
		&created, &expires, &revoked, &lu, &t.RemoteControl); err != nil {
		return nil, err
	}
	if scopes != "" {
		t.Scopes = strings.Split(scopes, ",")
	}
	t.CreatedAt = timeFromMS(created)
	t.ExpiresAt = ptrTime(expires)
	t.RevokedAt = ptrTime(revoked)
	t.LastUsedAt = ptrTime(lu)
	return &t, nil
}

// GetToken implements Store.
func (s *SQLite) GetToken(ctx context.Context, id string) (*Token, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("token %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: get token: %w", err)
	}
	return t, nil
}

// ListTokens implements Store.
func (s *SQLite) ListTokens(ctx context.Context) ([]*Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM tokens ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list tokens: %w", err)
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list tokens: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list tokens: %w", err)
	}
	return out, nil
}

// RevokeToken implements Store. The id is tried first, then the name among active tokens.
func (s *SQLite) RevokeToken(ctx context.Context, idOrName string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: revoke token: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	ms := at.UnixMilli()
	var (
		name    string
		revoked sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `SELECT name, revoked_at FROM tokens WHERE id = ?`, idOrName).Scan(&name, &revoked)
	switch {
	case err == nil:
		// An already revoked id changes nothing: its name may belong to a newer token by now.
		if !revoked.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE tokens SET revoked_at = ? WHERE id = ?`, ms, idOrName); err != nil {
				return fmt.Errorf("store: revoke token: %w", err)
			}
			if err := deleteReservations(ctx, tx, name); err != nil {
				return err
			}
		}
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx,
			`UPDATE tokens SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL`, ms, idOrName)
		if err != nil {
			return fmt.Errorf("store: revoke token: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: revoke token: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("token %q: %w", idOrName, ErrNotFound)
		}
		if err := deleteReservations(ctx, tx, idOrName); err != nil {
			return err
		}
	default:
		return fmt.Errorf("store: revoke token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: revoke token: %w", err)
	}
	return nil
}

func deleteReservations(ctx context.Context, tx *sql.Tx, client string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM port_reservations WHERE client = ?`, client); err != nil {
		return fmt.Errorf("store: delete port reservations: %w", err)
	}
	return nil
}

// HoldPort implements Store.
func (s *SQLite) HoldPort(ctx context.Context, client, tunnel string, port int, now time.Time, ttl time.Duration) error {
	if client == "" || tunnel == "" || port <= 0 || port > 65535 {
		return errors.New("store: port reservation needs client, tunnel and a valid port")
	}
	if len(client) > maxFieldLen || len(tunnel) > maxFieldLen {
		return errors.New("store: port reservation field too long")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: hold port: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Free the port if another tunnel's reservation of it has run out.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM port_reservations
		 WHERE port = ? AND NOT (client = ? AND tunnel = ?) AND released_at IS NOT NULL AND released_at + ? <= ?`,
		port, client, tunnel, ttl.Milliseconds(), now.UnixMilli()); err != nil {
		return fmt.Errorf("store: hold port: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO port_reservations (client, tunnel, port, released_at) VALUES (?, ?, ?, NULL)
		 ON CONFLICT (client, tunnel) DO UPDATE SET port = excluded.port, released_at = NULL`,
		client, tunnel, port); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("port %d: %w", port, ErrPortHeld)
		}
		return fmt.Errorf("store: hold port: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: hold port: %w", err)
	}
	return nil
}

// ReleasePort implements Store.
func (s *SQLite) ReleasePort(ctx context.Context, client, tunnel string, at time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE port_reservations SET released_at = ? WHERE client = ? AND tunnel = ?`,
		at.UnixMilli(), client, tunnel); err != nil {
		return fmt.Errorf("store: release port: %w", err)
	}
	return nil
}

// LoadPortReservations implements Store.
func (s *SQLite) LoadPortReservations(ctx context.Context, now time.Time, ttl time.Duration) ([]PortReservation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: load port reservations: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	ms := now.UnixMilli()
	if _, err := tx.ExecContext(ctx, `UPDATE port_reservations SET released_at = ? WHERE released_at IS NULL`, ms); err != nil {
		return nil, fmt.Errorf("store: load port reservations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM port_reservations WHERE released_at + ? <= ?`, ttl.Milliseconds(), ms); err != nil {
		return nil, fmt.Errorf("store: load port reservations: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT client, tunnel, port, released_at FROM port_reservations ORDER BY client, tunnel`)
	if err != nil {
		return nil, fmt.Errorf("store: load port reservations: %w", err)
	}
	defer rows.Close()
	var out []PortReservation
	for rows.Next() {
		var (
			r        PortReservation
			released int64
		)
		if err := rows.Scan(&r.Client, &r.Tunnel, &r.Port, &released); err != nil {
			return nil, fmt.Errorf("store: load port reservations: %w", err)
		}
		r.ReleasedAt = timeFromMS(released)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: load port reservations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: load port reservations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: load port reservations: %w", err)
	}
	return out, nil
}

// TouchToken implements Store.
func (s *SQLite) TouchToken(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`, at.UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("store: touch token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: touch token: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("token %q: %w", id, ErrNotFound)
	}
	return nil
}

// Close implements Store.
func (s *SQLite) Close() error { return s.db.Close() }
