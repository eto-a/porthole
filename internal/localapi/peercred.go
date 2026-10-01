// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"context"
	"net"
)

// Cred is the identity of the process on the other end of a unix socket connection.
// A field that the platform cannot provide is -1 (on macOS the PID or the GID may be unavailable).
type Cred struct {
	UID int
	GID int
	PID int
}

// PeerCred returns the credentials of the peer of c (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS). The second
// result is false when c is not a unix socket connection or the platform has no peer credentials (Windows).
func PeerCred(c net.Conn) (Cred, bool) { return peerCred(c) }

type credKey struct{}

// ConnContext is an http.Server.ConnContext function that stores the peer credentials of the connection in the
// context. [Serve] installs it; handlers read the result with [PeerCredFromContext].
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if cred, ok := PeerCred(c); ok {
		return context.WithValue(ctx, credKey{}, cred)
	}
	return ctx
}

// PeerCredFromContext returns the credentials stored by [ConnContext].
func PeerCredFromContext(ctx context.Context) (Cred, bool) {
	cred, ok := ctx.Value(credKey{}).(Cred)
	return cred, ok
}

// peerAttrs returns slog key/values describing the caller of a request, for audit-style logging.
func peerAttrs(ctx context.Context) []any {
	cred, ok := PeerCredFromContext(ctx)
	if !ok {
		return nil
	}
	return []any{"peer_uid", cred.UID, "peer_gid", cred.GID, "peer_pid", cred.PID}
}
