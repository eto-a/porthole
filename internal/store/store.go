// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package store persists server state: client tokens (v0.1) and port reservations (v0.2).
package store

import (
	"context"
	"errors"
	"slices"
	"time"
)

// Errors returned by Store implementations. Callers compare with errors.Is.
var (
	ErrNotFound  = errors.New("store: not found")
	ErrNameTaken = errors.New("store: name already in use")
	ErrRevoked   = errors.New("store: token revoked")
	ErrExpired   = errors.New("store: token expired")
	ErrPortHeld  = errors.New("store: port reserved for another tunnel")
	// ErrLabelClaimed means the hostname label (or SSH address) belongs for good to another (client, tunnel) pair.
	ErrLabelClaimed = errors.New("store: label claimed by another tunnel")
	// ErrLabelLimit means the client would hold more permanent labels than the server allows.
	ErrLabelLimit = errors.New("store: too many permanent labels")

	// Join code errors, from RedeemJoinCode. A wrong secret is ErrNotFound, indistinguishable from an unknown id.
	ErrJoinUsed    = errors.New("store: join code already used")
	ErrJoinExpired = errors.New("store: join code expired")
	ErrJoinRevoked = errors.New("store: join code revoked")
)

// Token is a client identity. The secret itself is never stored, only its sha256.
type Token struct {
	ID         string // public part of ph_<id>_<secret>
	Name       string // unique client name, e.g. "home"
	SecretHash []byte // sha256(secret)
	Last4      string // last 4 chars of the secret, for display
	Scopes     []string
	MaxTunnels int // 0 = server default
	CreatedAt  time.Time
	ExpiresAt  *time.Time // nil = never
	RevokedAt  *time.Time // nil = active
	LastUsedAt *time.Time // nil = never used
	// RemoteControl says that the machine accepts tunnels opened remotely by an operator (ADR 0005). Tokens made by a
	// join link get it from the link; `portholed token create` sets it unless given --no-remote-control.
	RemoteControl bool
	// CreatedBy is the id of the admin token whose join link made this token, "socket" for the admin socket, or empty.
	CreatedBy string
}

// PortReservation is a public TCP port remembered for the tunnel (Client, Tunnel).
type PortReservation struct {
	Client     string
	Tunnel     string
	Port       int
	ReleasedAt time.Time // when the tunnel went away; the reservation lasts a TTL from here
}

// LabelClaim is a hostname label or SSH gateway address that belongs for good to the tunnel (Client, Tunnel): the
// first pair that registered it. Labels are "<tunnel>-<client>" and both parts may contain hyphens, so two different
// pairs can compose the same one; the claim makes the first win for as long as its client token lives.
type LabelClaim struct {
	Label     string
	Client    string
	Tunnel    string
	ClaimedAt time.Time
	// LastUsedAt is the last registration of the tunnel (zero: never since the claim was created).
	LastUsedAt time.Time
}

// ClaimOwner identifies the tunnel that owns label claims.
type ClaimOwner struct {
	Client string
	Tunnel string
}

// Usable returns nil if the token may be used at now, ErrRevoked or ErrExpired otherwise.
func (t *Token) Usable(now time.Time) error {
	if t.RevokedAt != nil {
		return ErrRevoked
	}
	if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

// HasScope reports whether the token grants scope.
func (t *Token) HasScope(scope string) bool { return slices.Contains(t.Scopes, scope) }

// Store is the persistence interface used by the server and the admin CLI.
// Implementations must be safe for concurrent use, and for use by several processes on the same data
// (the token CLI runs alongside a live server).
type Store interface {
	// CreateToken inserts t. It returns ErrNameTaken if an active (non-revoked) token already has t.Name.
	CreateToken(ctx context.Context, t *Token) error
	// GetToken returns the token with the given id, or ErrNotFound.
	GetToken(ctx context.Context, id string) (*Token, error)
	// ListTokens returns all tokens, including revoked ones, ordered by CreatedAt.
	ListTokens(ctx context.Context) ([]*Token, error)
	// RevokeToken marks the token identified by id or by name as revoked at the given time and deletes the port
	// reservations and label claims of its client. It returns ErrNotFound if no active token matches. Revoking is idempotent for
	// already revoked ids.
	RevokeToken(ctx context.Context, idOrName string, at time.Time) error
	// TouchToken records the last successful use of a token.
	TouchToken(ctx context.Context, id string, at time.Time) error
	// HoldPort records that the live tunnel (client, tunnel) uses port. A row of another tunnel holding the same
	// port is replaced only if its reservation expired at now (released more than ttl ago); otherwise it returns
	// ErrPortHeld.
	HoldPort(ctx context.Context, client, tunnel string, port int, now time.Time, ttl time.Duration) error
	// ReleasePort starts the reservation period of (client, tunnel) at the given time. Unknown tunnels are ignored.
	ReleasePort(ctx context.Context, client, tunnel string, at time.Time) error
	// LoadPortReservations is called once at server start: it marks rows of tunnels that were still live (the
	// previous process died or stopped) as released at now, deletes reservations that expired, and returns the rest.
	LoadPortReservations(ctx context.Context, now time.Time, ttl time.Duration) ([]PortReservation, error)
	// ClaimLabels makes every label belong to (client, tunnel) in one transaction. A label already claimed by the
	// same pair is left alone; one claimed by another pair fails the whole call with ErrLabelClaimed and nothing is
	// claimed. It returns the labels this call newly claimed. A label equal to the name of another active token is
	// refused with ErrLabelClaimed: the bare name of a client is reserved for it. maxClaims > 0 bounds the number of
	// claims of client after the call; more fails with ErrLabelLimit. The claims the call leaves alone get
	// last_used_at = at.
	ClaimLabels(ctx context.Context, client, tunnel string, labels []string, at time.Time, maxClaims int) ([]string, error)
	// ExpireLabelClaims deletes the claims that were last used more than ttl before now (ttl <= 0: none) and
	// returns how many. The claims of the live tunnels are first marked as used at now.
	ExpireLabelClaims(ctx context.Context, now time.Time, ttl time.Duration, live []ClaimOwner) (int, error)
	// UnclaimLabels drops the claims of (client, tunnel) on labels; claims of other pairs are left alone.
	UnclaimLabels(ctx context.Context, client, tunnel string, labels []string) error
	// ReleaseLabel deletes the claim on label, whoever holds it. It returns ErrNotFound if there is none.
	ReleaseLabel(ctx context.Context, label string) error
	// AppendAudit adds e to the append-only admin audit log and sets e.ID.
	AppendAudit(ctx context.Context, e *AuditEntry) error
	// ListAudit returns the newest audit entries first; limit <= 0 means 100 and the maximum is 1000.
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)
	// CreateJoinCode inserts a one-time join code. It returns ErrNameTaken if an active token already has
	// jc.ClientName.
	CreateJoinCode(ctx context.Context, jc *JoinCode) error
	// RedeemJoinCode atomically spends the code id/secret at now and returns the permanent token it creates (and the
	// raw token string, shown once). Errors: ErrNotFound (unknown id or wrong secret), ErrJoinUsed, ErrJoinExpired,
	// ErrJoinRevoked, ErrNameTaken; on any error nothing is spent.
	RedeemJoinCode(ctx context.Context, id, secret string, now time.Time) (*Token, string, error)
	// ListJoinCodes returns all join codes ordered by CreatedAt.
	ListJoinCodes(ctx context.Context) ([]*JoinCode, error)
	// RevokeJoinCode marks the code revoked at the given time; revoking a used or revoked code changes nothing.
	// It returns ErrNotFound for an unknown id.
	RevokeJoinCode(ctx context.Context, id string, at time.Time) error
	// Close releases resources.
	Close() error
}
