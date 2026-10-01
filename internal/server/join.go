// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

const (
	maxJoinBody = 4 << 10
	auditAction = "join.redeem"
)

func isJoinPage(p string) bool { return strings.HasPrefix(p, proto.JoinPagePrefix) }

// serveJoinPage answers GET /j/<code> with the command to run. It never redeems the code, so link previews and
// crawlers that fetch the URL cannot spend it.
func (s *Server) serveJoinPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	code := strings.TrimPrefix(r.URL.Path, proto.JoinPagePrefix)
	if _, err := auth.ParseJoin(code); err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex")
	link := adminapi.JoinLink(s.cfg.PublicURL(), code)
	//nolint:gosec // text/plain, and the code was validated as [a-z2-7_] by ParseJoin
	_, _ = fmt.Fprintf(w, "This is a one-time porthole join link. To enrol a machine, run on it:\n\n    porthole join %s\n\n"+
		"The link works once and expires soon after it was created.\n", link)
}

// handleJoin redeems a join code: POST {"code": "pj_..."} returns the permanent token of the new client.
func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if s.ctx.Err() != nil {
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJoinError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	ip := ipOf(s.visitorAddr(r))
	if wait, blocked := s.limiter.blocked(surfaceJoin, ip, s.now()); blocked {
		s.log.Warn("join refused: too many failed attempts", "ip", ip)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
		writeJoinError(w, http.StatusTooManyRequests, proto.CodeRateLimited, "too many failed attempts; try again later")
		return
	}
	var req proto.JoinRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJoinBody))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	code, perr := auth.ParseJoin(strings.TrimSpace(req.Code))
	if err != nil || perr != nil {
		s.limiter.fail(surfaceJoin, ip, s.now())
		writeJoinError(w, http.StatusBadRequest, proto.CodeInvalidJoinCode, "not a porthole join code")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), storeTimeout)
	defer cancel()
	tok, raw, err := s.store.RedeemJoinCode(ctx, code.ID, code.Secret, s.now())
	if err != nil {
		s.joinFailed(w, r, ip, code.ID, err)
		return
	}
	s.auditJoin(code.ID, tok.Name, ip, "ok")
	s.log.Info("join code redeemed", "join_id", code.ID, "client", tok.Name, "token_id", tok.ID, "ip", ip)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(proto.JoinResponse{ServerURL: s.cfg.PublicURL(), ClientName: tok.Name, Token: raw})
}

// joinFailed maps a redemption error to a response. The error codes are stable; the message is for people.
func (s *Server) joinFailed(w http.ResponseWriter, _ *http.Request, ip, id string, err error) {
	var (
		status int
		code   string
		msg    string
	)
	switch {
	case errors.Is(err, store.ErrNotFound):
		status, code, msg = http.StatusNotFound, proto.CodeInvalidJoinCode, "unknown or wrong join code"
	case errors.Is(err, store.ErrJoinUsed):
		status, code, msg = http.StatusGone, proto.CodeJoinUsed, "this join link was already used; ask for a new one"
	case errors.Is(err, store.ErrJoinExpired):
		status, code, msg = http.StatusGone, proto.CodeJoinExpired, "this join link has expired; ask for a new one"
	case errors.Is(err, store.ErrJoinRevoked):
		status, code, msg = http.StatusGone, proto.CodeJoinRevoked, "this join link was revoked; ask for a new one"
	case errors.Is(err, store.ErrNameTaken):
		status, code, msg = http.StatusConflict, proto.CodeNameTaken, "a client with this name is already enrolled; ask the operator to revoke it first"
	default:
		s.log.Error("join redemption failed", "join_id", id, "err", err)
		writeJoinError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.limiter.fail(surfaceJoin, ip, s.now())
	s.log.Warn("join refused", "join_id", id, "ip", ip, "code", code)
	// A wrong secret is not recorded: anyone can send any id, and the audit log must not be fillable that way.
	if !errors.Is(err, store.ErrNotFound) {
		s.auditJoin(id, "", ip, "error: "+code)
	}
	writeJoinError(w, status, code, msg)
}

// auditJoin appends a join.redeem record: actor is the join id (the code is the only credential the caller has).
func (s *Server) auditJoin(id, client, ip, result string) {
	args, _ := json.Marshal(map[string]string{"remote": ip})
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), storeTimeout)
	defer cancel()
	e := &store.AuditEntry{At: s.now(), Actor: id, Action: auditAction, Target: client, Args: string(args), Result: result}
	if err := s.store.AppendAudit(ctx, e); err != nil {
		s.log.Error("audit write failed", "action", auditAction, "actor", id, "result", result, "err", err)
	}
}

func writeJoinError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	var b adminapi.ErrorBody
	b.Error.Code, b.Error.Message = code, msg
	_ = json.NewEncoder(w).Encode(b)
}
