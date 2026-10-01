// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/store"
)

// Limits of a join code, so that a typo cannot create a link that lives for years.
const (
	minJoinTTL = time.Minute
	maxJoinTTL = 7 * 24 * time.Hour
	// maxTokenDays keeps now+token_expires_in far from time overflow (same bound as `portholed token create`).
	maxTokenDays = 36500
)

// JoinRequest is the body of POST join. Durations are strings such as "15m", "2h" or "30d".
type JoinRequest struct {
	ClientName     string   `json:"client_name"`
	Scopes         []string `json:"scopes,omitempty"`           // default: the tunnel scopes
	TTL            string   `json:"ttl,omitempty"`              // life of the link; default 15m
	MaxTunnels     int      `json:"max_tunnels,omitempty"`      // 0 = server default
	TokenExpiresIn string   `json:"token_expires_in,omitempty"` // life of the token created by the link; default: never
	RemoteControl  *bool    `json:"remote_control,omitempty"`   // accept tunnels opened remotely; default true
}

// JoinCreated is the response of POST join. The link is shown once: the server keeps only a hash of the code.
type JoinCreated struct {
	ID         string    `json:"id"`
	Link       string    `json:"link"`
	Command    string    `json:"command"` // "porthole join <link>"
	ClientName string    `json:"client_name"`
	ExpiresAt  time.Time `json:"expires_at"`
	// TokenExpiresAt is when the token the link creates expires; nil = never. A bearer token's request is capped at
	// the creator's own expiry, so it may be earlier than asked.
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
}

// JoinCode describes one join code in the list. It never holds the code or its hash.
type JoinCode struct {
	ID             string     `json:"id"`
	ClientName     string     `json:"client_name"`
	Scopes         []string   `json:"scopes"`
	MaxTunnels     int        `json:"max_tunnels"`
	TokenExpiresAt *time.Time `json:"token_expires_at"`
	RemoteControl  bool       `json:"remote_control"`
	Status         string     `json:"status"` // active, used, revoked or expired
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	UsedAt         *time.Time `json:"used_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	CreatedBy      string     `json:"created_by"`
}

// mountJoin registers the join endpoints. They all need admin:tokens: a join link is a way to mint a token.
func (a *API) mountJoin() {
	p := Prefix + "/join"
	a.routes.HandleFunc("POST "+p, a.createJoin)
	a.read("GET "+p, auth.ScopeAdminTokens, a.listJoin)
	a.mutate("POST "+p+"/{id}/revoke", auth.ScopeAdminTokens, "join.revoke", "id", a.revokeJoin)
}

// JoinLink returns the link for a join code string under serverURL: <server_url>/j/<code>.
func JoinLink(serverURL, code string) string {
	return strings.TrimSuffix(serverURL, "/") + "/j/" + code
}

func (a *API) createJoin(w http.ResponseWriter, r *http.Request) {
	const action = "join.create"
	p := principalOf(r)
	if !p.allows(auth.ScopeAdminTokens) {
		a.record(r.Context(), p, action, "", a.auditArgs(r, p), "denied")
		writeError(w, http.StatusForbidden, "forbidden", "token lacks scope "+auth.ScopeAdminTokens)
		return
	}
	var req JoinRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		err = dec.Decode(&req)
	}
	if err != nil {
		a.record(r.Context(), p, action, "", a.auditArgs(r, p), "error: invalid_request")
		writeError(w, http.StatusBadRequest, "invalid_request", "body must be a JSON object with client_name and optional scopes, ttl, max_tunnels, token_expires_in, remote_control")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), storeTimeout)
	defer cancel()
	created, jc, err := a.newJoin(ctx, p, &req)
	args := a.joinAuditArgs(r, p, &req)
	if err != nil {
		status, code, msg := classify(err)
		a.record(r.Context(), p, action, "", args, "error: "+code)
		if status == http.StatusInternalServerError {
			a.log.Error("admin action failed", "action", action, "err", err)
		}
		writeError(w, status, code, msg)
		return
	}
	a.record(r.Context(), p, action, jc.ID, args, "ok")
	writeJSON(w, http.StatusOK, created)
}

// newJoin validates req, stores the code and returns the response.
func (a *API) newJoin(ctx context.Context, p principal, req *JoinRequest) (*JoinCreated, *store.JoinCode, error) {
	return newJoinCode(ctx, a.st, a.serverURL, a.maxTunnels, a.now(), p, req)
}

// newJoinCode is newJoin without the API: the admin API and the MCP server share it.
//
// A caller that is not trusted (a bearer token) cannot make a token more powerful or longer-lived than itself: no admin
// scopes, connect:<client> only for clients it may connect to, at most maxTunnels tunnels, and neither the link nor
// the minted token outlives the caller's own token. Only the admin socket is exempt.
func newJoinCode(ctx context.Context, st Store, serverURL string, maxTunnels int, now time.Time, p principal, req *JoinRequest) (*JoinCreated, *store.JoinCode, error) {
	if !auth.ValidName(req.ClientName) {
		return nil, nil, errBadRequest("client_name must be 1-32 characters of a-z, 0-9 and '-', not starting or ending with '-'")
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = auth.DefaultScopes
	}
	scopes, err := checkScopes(p, scopes)
	if err != nil {
		return nil, nil, err
	}
	if req.MaxTunnels < 0 {
		return nil, nil, errBadRequest("max_tunnels must not be negative")
	}
	if !p.trusted && maxTunnels > 0 && req.MaxTunnels > maxTunnels {
		return nil, nil, errBadRequest(fmt.Sprintf("max_tunnels must not exceed the server limit of %d", maxTunnels))
	}
	ttl := store.DefaultJoinTTL
	if req.TTL != "" {
		if ttl, err = parseDuration(req.TTL); err != nil {
			return nil, nil, errBadRequest("ttl: " + err.Error())
		}
		if ttl < minJoinTTL || ttl > maxJoinTTL {
			return nil, nil, errBadRequest(fmt.Sprintf("ttl must be between %s and %s", minJoinTTL, maxJoinTTL))
		}
	}
	var tokExp *time.Time
	if req.TokenExpiresIn != "" && req.TokenExpiresIn != "0" {
		d, err := parseDuration(req.TokenExpiresIn)
		if err != nil {
			return nil, nil, errBadRequest("token_expires_in: " + err.Error())
		}
		if d <= ttl {
			return nil, nil, errBadRequest("token_expires_in must be longer than ttl, or the token could expire before the link is used")
		}
		t := now.Add(d)
		tokExp = &t
	}
	if !p.trusted && p.tok != nil && p.tok.ExpiresAt != nil {
		limit := *p.tok.ExpiresAt
		if !limit.After(now.Add(minJoinTTL)) {
			return nil, nil, errForbidden("the calling token expires too soon to create a join link")
		}
		if tokExp == nil || tokExp.After(limit) {
			tokExp = &limit
		}
		ttl = min(ttl, limit.Sub(now))
	}
	remote := req.RemoteControl == nil || *req.RemoteControl

	code, err := auth.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("adminapi: generate join code: %w", err)
	}
	jc := &store.JoinCode{
		ID: code.ID, CodeHash: code.Hash(), ClientName: req.ClientName, Scopes: scopes, MaxTunnels: req.MaxTunnels,
		TokenExpiresAt: tokExp, RemoteControl: remote, CreatedAt: now, ExpiresAt: now.Add(ttl), CreatedBy: p.actor,
	}
	if err := st.CreateJoinCode(ctx, jc); err != nil {
		if errors.Is(err, store.ErrNameTaken) {
			return nil, nil, errConflict("an active token already uses the name " + strconv.Quote(req.ClientName))
		}
		return nil, nil, err
	}
	link := JoinLink(serverURL, code.JoinString())
	return &JoinCreated{
		ID: jc.ID, Link: link, Command: "porthole join " + link, ClientName: jc.ClientName, ExpiresAt: jc.ExpiresAt.UTC(),
		TokenExpiresAt: tokExp,
	}, jc, nil
}

// checkScopes validates the scopes of a join code and stops a caller from handing out more than it has. A bearer
// token may grant tunnel scopes, and connect:<client> only if it holds that scope or is that client; admin scopes it
// may never grant (else a token with admin:tokens could mint itself a permanent copy that survives its revocation).
// The socket may grant anything.
func checkScopes(p principal, in []string) ([]string, error) {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if !auth.ValidScope(s) {
			return nil, errBadRequest("unknown scope " + strconv.Quote(s))
		}
		if !p.trusted {
			if strings.HasPrefix(s, "admin:") {
				return nil, errForbidden("cannot grant scope " + s + ": admin scopes can only be granted through the local admin socket")
			}
			if client, ok := strings.CutPrefix(s, "connect:"); ok && !p.allows(s) && p.name() != client {
				return nil, errForbidden("cannot grant scope " + s + ": the calling token neither holds it nor is that client")
			}
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// joinAuditArgs describes the create call for the audit log: no secret exists yet at this point, and none is logged.
func (a *API) joinAuditArgs(r *http.Request, p principal, req *JoinRequest) string {
	m := map[string]any{
		"client_name": req.ClientName, "scopes": req.Scopes, "ttl": req.TTL, "max_tunnels": req.MaxTunnels,
		"token_expires_in": req.TokenExpiresIn, "remote_control": req.RemoteControl == nil || *req.RemoteControl,
	}
	if !p.trusted {
		m["remote"] = a.ip(r)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (a *API) listJoin(ctx context.Context, _ *http.Request) (any, error) {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	codes, err := a.st.ListJoinCodes(sctx)
	if err != nil {
		return nil, err
	}
	now := a.now()
	out := make([]JoinCode, 0, len(codes))
	for _, c := range codes {
		out = append(out, JoinCode{
			ID: c.ID, ClientName: c.ClientName, Scopes: nonNil(c.Scopes), MaxTunnels: c.MaxTunnels,
			TokenExpiresAt: c.TokenExpiresAt, RemoteControl: c.RemoteControl, Status: c.Status(now),
			CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt, UsedAt: c.UsedAt, RevokedAt: c.RevokedAt, CreatedBy: c.CreatedBy,
		})
	}
	return map[string]any{"join_codes": out}, nil
}

func (a *API) revokeJoin(ctx context.Context, id string) error {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	return a.st.RevokeJoinCode(sctx, id, a.now())
}

// parseDuration parses "15m", "2h" and day counts such as "30d".
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseFloat(days, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 || n > maxTokenDays {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > maxTokenDays*24*time.Hour {
		return 0, fmt.Errorf("invalid duration %q: want e.g. 15m, 2h or 30d", s)
	}
	return d, nil
}

// Grantor is who creates a join link outside the HTTP API (the operator MCP server). It limits the scopes the link
// may hand out exactly as the API does for its callers.
type Grantor struct {
	// Actor is recorded as the creator of the link.
	Actor string
	// Trusted callers (the admin socket, an unauthenticated stdio server) may grant any scope.
	Trusted bool
	// Scopes are the scopes the caller holds; ignored when Trusted.
	Scopes []string
	// Name is the client name of the caller's token (it may be granted connect:<Name>); ignored when Trusted.
	Name string
	// ExpiresAt is the expiry of the caller's token, nil for none; links and minted tokens are capped by it.
	ExpiresAt *time.Time
	// MaxTunnels is the server's per-client limit (0 = none), the cap for MaxTunnels of the link.
	MaxTunnels int
}

// CreateJoin validates req and stores a one-time join code under the same rules as POST join, and returns the link.
// serverURL is the public URL the link is built on. Failures are *Error with the codes the API uses
// (invalid_request, forbidden, conflict).
func CreateJoin(ctx context.Context, st Store, serverURL string, now time.Time, g Grantor, req JoinRequest) (JoinCreated, error) {
	p := principal{actor: g.Actor, trusted: g.Trusted, tok: &store.Token{Name: g.Name, Scopes: g.Scopes, ExpiresAt: g.ExpiresAt}}
	created, _, err := newJoinCode(ctx, st, serverURL, g.MaxTunnels, now, p, &req)
	if err != nil {
		status, code, msg := classify(err)
		if status == http.StatusInternalServerError {
			return JoinCreated{}, err
		}
		return JoinCreated{}, &Error{HTTPStatus: status, Code: code, Message: msg}
	}
	return *created, nil
}
