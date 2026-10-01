// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package adminapi is the server's management API (ADR 0005): HTTP+JSON over a local unix socket (access is the
// file permission, full admin) and over the public listener under Prefix (bearer token with admin:* scopes). It is
// the only management path; the CLI and the MCP surfaces are thin clients of it.
//
// The package knows nothing about the server's internals: it talks to a Backend (live state) and a Store
// (persistent state), both supplied by the caller.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/traffic"
)

const (
	// Prefix is the path prefix of every endpoint, on the socket and on the public listener alike.
	Prefix = "/_porthole/admin/v1"
	// ActorSocket is the audit actor of calls that arrive on the unix socket.
	ActorSocket = "socket"

	storeTimeout   = 5 * time.Second
	backendTimeout = 10 * time.Second
	maxBodyBytes   = 1 << 10
)

// Errors that Backend and Options.Authenticate implementations return.
var (
	// ErrNotFound reports an unknown client, tunnel or token (HTTP 404).
	ErrNotFound = errors.New("adminapi: not found")
	// ErrUnauthorized reports a missing, malformed, unknown, revoked or expired token (HTTP 401).
	ErrUnauthorized = errors.New("adminapi: unauthorized")
)

// ConflictError reports a request that is valid but cannot be carried out in the current state (HTTP 409); its
// message is shown to the caller.
type ConflictError struct{ Message string }

func (e *ConflictError) Error() string { return "adminapi: " + e.Message }

// RateLimitedError is returned by Options.Authenticate when the caller has failed too often (HTTP 429).
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("adminapi: too many failed attempts, retry after %s", e.RetryAfter)
}

// Backend is the live state the API reads and acts on. The server implements it over its registry.
// Implementations must be safe for concurrent use.
type Backend interface {
	// Status returns the server version, uptime and counters.
	Status(ctx context.Context) (Status, error)
	// Clients lists the connected clients (one session per client name), ordered by name.
	Clients(ctx context.Context) ([]Client, error)
	// Disconnect drops the connection of the named client; the client may reconnect. ErrNotFound if it is offline.
	Disconnect(ctx context.Context, name string) error
	// Tunnels lists the registered tunnels, ordered by client and name.
	Tunnels(ctx context.Context) ([]Tunnel, error)
	// CloseTunnel closes the tunnel with the given id and tells its client. ErrNotFound if there is none.
	CloseTunnel(ctx context.Context, id string) error

	// Requests returns the logged HTTP requests matching f, newest first, without details.
	Requests(ctx context.Context, f traffic.RequestFilter) ([]traffic.Request, error)
	// RequestAggregates summarises the requests matching f; top lists hold at most topN entries.
	RequestAggregates(ctx context.Context, f traffic.RequestFilter, topN int) (traffic.Aggregates, error)
	// Request returns one logged request with its Detail (nil unless the request was inspected). ErrNotFound if
	// it is no longer in the log. The API drops Detail for callers without the admin:traffic scope.
	Request(ctx context.Context, id uint64) (traffic.Request, error)
	// ReplayRequest sends the recorded request again into its tunnel and returns the new log entry. It returns
	// ErrNotFound for an unknown id and a *ConflictError when the request cannot be replayed (not inspected,
	// body truncated, tunnel offline).
	ReplayRequest(ctx context.Context, id uint64) (traffic.Request, error)
	// Connections returns the logged TCP and SSH connections matching f, newest first.
	Connections(ctx context.Context, f traffic.ConnFilter) ([]traffic.Conn, error)
	// AuthFailures returns the SSH gateway authentication failures since the given time (zero for all), newest
	// first, at most limit of them (0 is the default).
	AuthFailures(ctx context.Context, since time.Time, limit int) ([]traffic.Conn, error)
	// RequestTunnel asks the named client to open a tunnel on its machine and waits for the outcome (at most 15 s).
	// ErrNotFound if the client is offline; *RemoteError if the request cannot be carried out.
	RequestTunnel(ctx context.Context, client string, req RemoteOpen) (RemoteTunnel, error)
}

// SessionCloser is implemented by a Backend that can end the live sessions of a token. The API calls it after a
// token is revoked, so that revoking takes effect at once and not at the next revalidation of the session.
type SessionCloser interface {
	// TokenRevoked closes every session that authenticated with the token id and tells its client why.
	TokenRevoked(ctx context.Context, tokenID string)
}

// Store is the persistent state the API needs; store.Store satisfies it.
type Store interface {
	GetToken(ctx context.Context, id string) (*store.Token, error)
	ListTokens(ctx context.Context) ([]*store.Token, error)
	RevokeToken(ctx context.Context, idOrName string, at time.Time) error
	AppendAudit(ctx context.Context, e *store.AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]store.AuditEntry, error)
	CreateJoinCode(ctx context.Context, jc *store.JoinCode) error
	ListJoinCodes(ctx context.Context) ([]*store.JoinCode, error)
	RevokeJoinCode(ctx context.Context, id string, at time.Time) error
	ReleaseLabel(ctx context.Context, label string) error
}

// Status is the GET status response.
type Status struct {
	Version       string    `json:"version"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	Clients       int       `json:"clients"`
	Tunnels       int       `json:"tunnels"`
}

// Client is a connected client.
type Client struct {
	Name          string    `json:"name"`
	SessionID     string    `json:"session_id"`
	TokenID       string    `json:"token_id"`
	Remote        string    `json:"remote"`
	ConnectedAt   time.Time `json:"connected_at"`
	ClientVersion string    `json:"client_version,omitempty"`
	OS            string    `json:"os,omitempty"`
	Tunnels       int       `json:"tunnels"`
}

// Tunnel is a registered tunnel.
type Tunnel struct {
	ID      string `json:"id"`
	Client  string `json:"client"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	URL     string `json:"url,omitempty"`
	Port    int    `json:"port,omitempty"`
	Private bool   `json:"private,omitempty"`
	Inspect bool   `json:"inspect,omitempty"` // HTTP: request and response bodies are stored for the inspector
}

// Token is a token as the API shows it: never the secret or its hash.
type Token struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Last4      string     `json:"last4"`
	Scopes     []string   `json:"scopes"`
	MaxTunnels int        `json:"max_tunnels"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// RemoteControl: operators may open tunnels on this token's client remotely.
	// CreatedBy is the id of the token whose join link made this one, "socket", or empty.
	CreatedBy     string `json:"created_by,omitempty"`
	RemoteControl bool   `json:"remote_control"`
}

// AuditEntry is one audit log record.
type AuditEntry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Args   string    `json:"args,omitempty"`
	Result string    `json:"result"`
}

// Options configures New.
type Options struct {
	Backend Backend
	Store   Store
	// Authenticate resolves a bearer secret ("ph_<id>_<secret>") to an active token. It returns ErrUnauthorized,
	// *RateLimitedError or any other error (HTTP 500). ip is the caller's address, for rate limiting.
	Authenticate func(ctx context.Context, ip, raw string) (*store.Token, error)
	// ClientIP extracts the caller's address from a request (it may honour proxy headers). Default: RemoteAddr.
	ClientIP func(r *http.Request) string
	Now      func() time.Time
	Logger   *slog.Logger
	// ServerURL is the address clients connect to, the base of join links ("https://tun.example.com").
	ServerURL string
	// MaxTunnelsPerClient is the server's per-client tunnel limit. A join link made with a bearer token cannot grant
	// more; 0 means no limit.
	MaxTunnelsPerClient int
}

// API serves the admin endpoints.
type API struct {
	be     Backend
	st     Store
	authn  func(ctx context.Context, ip, raw string) (*store.Token, error)
	ip     func(r *http.Request) string
	now    func() time.Time
	log    *slog.Logger
	routes *http.ServeMux

	serverURL  string
	maxTunnels int
}

// New builds the API. Backend, Store and Authenticate are required.
func New(opts Options) (*API, error) {
	if opts.Backend == nil || opts.Store == nil || opts.Authenticate == nil {
		return nil, errors.New("adminapi: Backend, Store and Authenticate are required")
	}
	a := &API{be: opts.Backend, st: opts.Store, authn: opts.Authenticate, ip: opts.ClientIP, now: opts.Now, log: opts.Logger, serverURL: opts.ServerURL, maxTunnels: opts.MaxTunnelsPerClient}
	if a.ip == nil {
		a.ip = func(r *http.Request) string {
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				return host
			}
			return r.RemoteAddr
		}
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = slog.New(slog.DiscardHandler)
	}
	a.routes = http.NewServeMux()
	a.mount()
	return a, nil
}

// principal is who is calling: a token with scopes, or the socket (everything).
type principal struct {
	actor   string
	tok     *store.Token
	trusted bool
}

// name is the client name of the caller's token ("" for the socket).
func (p principal) name() string {
	if p.tok == nil {
		return ""
	}
	return p.tok.Name
}

func (p principal) allows(scope string) bool {
	return p.trusted || (p.tok != nil && p.tok.HasScope(scope))
}

type principalKey struct{}

func principalOf(r *http.Request) principal {
	p, _ := r.Context().Value(principalKey{}).(principal)
	return p
}

// SocketHandler serves the API for the unix socket: no token, full access, actor "socket". Only hand it to a
// listener whose access is limited by file permissions.
func (a *API) SocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), principalKey{}, principal{actor: ActorSocket, trusted: true})
		a.routes.ServeHTTP(w, r.WithContext(ctx))
	})
}

// BearerHandler serves the API for the public listener: every request needs a valid token. Mount it for paths
// under Prefix.
func (a *API) BearerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="porthole-admin"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		tok, err := a.authn(r.Context(), a.ip(r), raw)
		var rl *RateLimitedError
		switch {
		case errors.As(err, &rl):
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int((rl.RetryAfter+time.Second-1)/time.Second))))
			writeError(w, http.StatusTooManyRequests, "limit_exceeded", "too many failed attempts")
			return
		case errors.Is(err, ErrUnauthorized):
			w.Header().Set("WWW-Authenticate", `Bearer realm="porthole-admin", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
			return
		case err != nil:
			a.log.Error("admin authentication failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, principal{actor: tok.ID, tok: tok})
		a.routes.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(h string) (string, bool) {
	scheme, raw, ok := strings.Cut(h, " ")
	raw = strings.TrimSpace(raw)
	if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" {
		return "", false
	}
	return raw, true
}

// mount registers the v1 endpoints.
func (a *API) mount() {
	p := Prefix
	a.read("GET "+p+"/status", auth.ScopeAdminRead, func(ctx context.Context, _ *http.Request) (any, error) {
		return a.be.Status(ctx)
	})
	a.read("GET "+p+"/clients", auth.ScopeAdminRead, func(ctx context.Context, _ *http.Request) (any, error) {
		cs, err := a.be.Clients(ctx)
		return map[string]any{"clients": nonNil(cs)}, err
	})
	a.read("GET "+p+"/tunnels", auth.ScopeAdminRead, func(ctx context.Context, _ *http.Request) (any, error) {
		ts, err := a.be.Tunnels(ctx)
		return map[string]any{"tunnels": nonNil(ts)}, err
	})
	a.read("GET "+p+"/tokens", auth.ScopeAdminRead, a.listTokens)
	a.read("GET "+p+"/audit", auth.ScopeAdminRead, a.listAudit)
	a.mountTraffic()

	a.mutate("POST "+p+"/clients/{name}/disconnect", auth.ScopeAdminClients, "client.disconnect", "name",
		func(ctx context.Context, name string) error { return a.be.Disconnect(ctx, name) })
	a.mutate("DELETE "+p+"/tunnels/{id}", auth.ScopeAdminTunnels, "tunnel.close", "id",
		func(ctx context.Context, id string) error { return a.be.CloseTunnel(ctx, id) })
	a.mutate("POST "+p+"/labels/{label}/release", auth.ScopeAdminTunnels, "label.release", "label", a.releaseLabel)
	a.mutate("POST "+p+"/tokens/{id}/revoke", auth.ScopeAdminTokens, "token.revoke", "id", a.revokeToken)
	a.routes.HandleFunc("POST "+p+"/clients/{name}/tunnels", a.remoteOpen)

	a.mountJoin()

	a.routes.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// read registers a GET endpoint that needs scope and returns a JSON value.
func (a *API) read(pattern, scope string, fn func(ctx context.Context, r *http.Request) (any, error)) {
	a.routes.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !principalOf(r).allows(scope) {
			writeError(w, http.StatusForbidden, "forbidden", "token lacks scope "+scope)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), backendTimeout)
		defer cancel()
		v, err := fn(ctx, r)
		if err != nil {
			a.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
}

// mutate registers an endpoint that changes state. Every call by an authenticated principal, allowed or not, is
// written to the audit log.
func (a *API) mutate(pattern, scope, action, param string, fn func(ctx context.Context, target string) error) {
	a.mutateValue(pattern, scope, action, param, func(ctx context.Context, target string) (any, error) {
		return map[string]bool{"ok": true}, fn(ctx, target)
	})
}

// mutateValue is mutate for an action whose success reply is a value.
func (a *API) mutateValue(pattern, scope, action, param string, fn func(ctx context.Context, target string) (any, error)) {
	a.routes.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r)
		target := r.PathValue(param)
		args := a.auditArgs(r, p)
		if !p.allows(scope) {
			a.record(r.Context(), p, action, target, args, "denied")
			writeError(w, http.StatusForbidden, "forbidden", "token lacks scope "+scope)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		ctx, cancel := context.WithTimeout(r.Context(), backendTimeout)
		defer cancel()
		v, err := fn(ctx, target)
		if err != nil {
			status, code, msg := classify(err)
			a.record(r.Context(), p, action, target, args, "error: "+code)
			if status == http.StatusInternalServerError {
				a.log.Error("admin action failed", "action", action, "target", target, "err", err)
			}
			writeError(w, status, code, msg)
			return
		}
		a.record(r.Context(), p, action, target, args, "ok")
		writeJSON(w, http.StatusOK, v)
	})
}

// auditArgs describes the call for the audit log. It never holds secrets: only the caller's address.
func (a *API) auditArgs(r *http.Request, p principal) string {
	if p.trusted {
		return "{}"
	}
	b, _ := json.Marshal(map[string]string{"remote": a.ip(r)})
	return string(b)
}

// record appends to the audit log. The caller's context may already be cancelled when the client hangs up, so the
// write gets its own deadline: a mutation that happened must be recorded.
func (a *API) record(ctx context.Context, p principal, action, target, args, result string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	e := &store.AuditEntry{At: a.now(), Actor: p.actor, Action: action, Target: target, Args: args, Result: result}
	if err := a.st.AppendAudit(ctx, e); err != nil {
		a.log.Error("audit write failed", "action", action, "target", target, "actor", p.actor, "result", result, "err", err)
	}
}

// releaseLabel frees a hostname label or SSH address that is claimed for good by its first (client, tunnel) pair.
func (a *API) releaseLabel(ctx context.Context, label string) error {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	return a.st.ReleaseLabel(sctx, label)
}

func (a *API) revokeToken(ctx context.Context, id string) error {
	return RevokeToken(ctx, a.st, a.be, id, a.now())
}

// RevokeToken revokes the token with this id (not a name) and closes its live sessions at once through be, if be can.
// The admin API and the MCP server share it.
func RevokeToken(ctx context.Context, st Store, be Backend, id string, now time.Time) error {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	if _, err := st.GetToken(sctx, id); err != nil {
		return err
	}
	if err := st.RevokeToken(sctx, id, now); err != nil {
		return err
	}
	if sc, ok := be.(SessionCloser); ok {
		sc.TokenRevoked(ctx, id)
	}
	return nil
}

func (a *API) listTokens(ctx context.Context, _ *http.Request) (any, error) {
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	toks, err := a.st.ListTokens(sctx)
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(toks))
	for _, t := range toks {
		out = append(out, Token{
			ID: t.ID, Name: t.Name, Last4: t.Last4, Scopes: nonNil(t.Scopes), MaxTunnels: t.MaxTunnels,
			CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, LastUsedAt: t.LastUsedAt, RemoteControl: t.RemoteControl, CreatedBy: t.CreatedBy,
		})
	}
	return map[string]any{"tokens": out}, nil
}

func (a *API) listAudit(ctx context.Context, r *http.Request) (any, error) {
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, errBadRequest("limit must be a positive integer")
		}
		limit = n
	}
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	var before int64
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return nil, errBadRequest("before must be a positive entry id")
		}
		before = n
	}
	var (
		es  []store.AuditEntry
		err error
	)
	if pager, ok := a.st.(store.AuditPager); ok {
		es, err = pager.ListAuditBefore(sctx, before, limit)
	} else if before > 0 {
		return nil, errBadRequest("this store cannot page the audit log")
	} else {
		es, err = a.st.ListAudit(sctx, limit)
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditEntry, 0, len(es))
	for _, e := range es {
		out = append(out, AuditEntry{ID: e.ID, At: e.At, Actor: e.Actor, Action: e.Action, Target: e.Target, Args: e.Args, Result: e.Result})
	}
	return map[string]any{"entries": out}, nil
}

type badRequestError string

func (e badRequestError) Error() string { return string(e) }

func errBadRequest(msg string) error { return badRequestError(msg) }

type forbiddenError string

func (e forbiddenError) Error() string { return string(e) }

func errForbidden(msg string) error { return forbiddenError(msg) }

type conflictError string

func (e conflictError) Error() string { return string(e) }

func errConflict(msg string) error { return conflictError(msg) }

// classify maps an error to an HTTP status, a stable error code and a message safe to show to the caller.
func classify(err error) (status int, code, msg string) {
	var (
		br badRequestError
		fb forbiddenError
		cf conflictError
		ce *ConflictError
	)
	switch {
	case errors.As(err, &br):
		return http.StatusBadRequest, "invalid_request", string(br)
	case errors.As(err, &fb):
		return http.StatusForbidden, "forbidden", string(fb)
	case errors.As(err, &cf):
		return http.StatusConflict, "conflict", string(cf)
	case errors.As(err, &ce):
		return http.StatusConflict, "conflict", ce.Message
	case errors.Is(err, ErrNotFound), errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not_found", "not found"
	default:
		return http.StatusInternalServerError, "internal", "internal error"
	}
}

func (a *API) fail(w http.ResponseWriter, err error) {
	status, code, msg := classify(err)
	if status == http.StatusInternalServerError {
		a.log.Error("admin request failed", "err", err)
	}
	writeError(w, status, code, msg)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ErrorBody is the JSON shape of every error response: {"error":{"code":"...","message":"..."}}.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var b ErrorBody
	b.Error.Code, b.Error.Message = code, msg
	writeJSON(w, status, b)
}
