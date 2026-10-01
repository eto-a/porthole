// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
)

const (
	// remoteTimeout bounds one remote open: the backend waits up to 15 s for the client (ADR 0005).
	remoteTimeout      = 20 * time.Second
	maxRemoteBodyBytes = 4 << 10

	// ActionRemoteOpen is the audit action of a remote tunnel request.
	ActionRemoteOpen = "tunnel.remote_open"

	// CodeRemoteDisabled is the error code when the client's token does not allow remote control.
	CodeRemoteDisabled = "remote_control_disabled"
)

// RemoteOpen asks a connected client to open a tunnel (POST .../clients/{name}/tunnels).
type RemoteOpen struct {
	// Kind is http, tcp or ssh.
	Kind string `json:"kind"`
	// LocalAddr is the target on the client's machine: a port, host:port, or "ssh" (127.0.0.1:22). Empty is allowed
	// for ssh only.
	LocalAddr  string `json:"local_addr,omitempty"`
	Name       string `json:"name,omitempty"`
	Private    bool   `json:"private,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	// RequestedBy is the acting token or "socket"; the API sets it, it is not read from the request body.
	RequestedBy string `json:"-"`
}

// RemoteTunnel is the tunnel a client opened on request.
type RemoteTunnel struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// URL is the public address (https URL for http, tcp://host:port for tcp, ssh target for ssh).
	URL string `json:"public_url"`
	// SSHJump is the host:port of the SSH gateway (kind ssh only).
	SSHJump string `json:"ssh_jump,omitempty"`
}

// RemoteError is returned by Backend.RequestTunnel when the request was understood but could not be carried out.
// Codes: proto.CodeClientUnsupported, proto.CodeTimeout, proto.CodeNotAllowed, proto.CodeNameTaken,
// proto.CodeInvalidRequest, proto.CodePortUnavailable, proto.CodeLimitExceeded, CodeRemoteDisabled. A client that
// is not connected is ErrNotFound.
type RemoteError struct{ Code, Message string }

func (e *RemoteError) Error() string { return e.Code + ": " + e.Message }

func (e *RemoteError) status() int {
	switch e.Code {
	case proto.CodeInvalidRequest:
		return http.StatusBadRequest
	case proto.CodeNotAllowed, CodeRemoteDisabled, proto.CodeForbidden:
		return http.StatusForbidden
	case proto.CodeNameTaken, proto.CodePortUnavailable, proto.CodeClientUnsupported:
		return http.StatusConflict
	case proto.CodeLimitExceeded:
		return http.StatusTooManyRequests
	case proto.CodeTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}

// remoteOpen serves POST /clients/{name}/tunnels.
func (a *API) remoteOpen(w http.ResponseWriter, r *http.Request) {
	const action = ActionRemoteOpen
	p := principalOf(r)
	client := r.PathValue("name")
	if !p.allows(auth.ScopeAdminRemote) {
		a.record(r.Context(), p, action, client, a.auditArgs(r, p), "denied")
		writeError(w, http.StatusForbidden, "forbidden", "token lacks scope "+auth.ScopeAdminRemote)
		return
	}
	var req RemoteOpen
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRemoteBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		a.record(r.Context(), p, action, client, a.auditArgs(r, p), "error: invalid_request")
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	req.RequestedBy = p.actor
	// Local addresses and names are not secrets; no credentials ever travel in this request.
	args, _ := json.Marshal(map[string]any{
		"kind": req.Kind, "local_addr": req.LocalAddr, "name": req.Name, "private": req.Private,
		"remote_port": req.RemotePort, "remote": a.ip(r),
	})
	ctx, cancel := context.WithTimeout(r.Context(), remoteTimeout)
	defer cancel()
	tun, err := a.be.RequestTunnel(ctx, client, req)
	if err != nil {
		var re *RemoteError
		switch {
		case errors.As(err, &re):
			a.record(r.Context(), p, action, client, string(args), "error: "+re.Code)
			writeError(w, re.status(), re.Code, re.Message)
		default:
			status, code, msg := classify(err)
			a.record(r.Context(), p, action, client, string(args), "error: "+code)
			if status == http.StatusInternalServerError {
				a.log.Error("admin action failed", "action", action, "target", client, "err", err)
			}
			if code == "not_found" {
				msg = "client is not connected"
			}
			writeError(w, status, code, msg)
		}
		return
	}
	a.record(r.Context(), p, action, client, string(args), "ok")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tunnel": tun})
}
