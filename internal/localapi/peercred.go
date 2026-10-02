// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"context"
	"net"
	"os/user"
	"strconv"
	"sync"
)

// Cred is the identity of the process on the other end of a local API connection.
//
// UID, GID and PID are -1 when the platform cannot provide them (on macOS the PID or the GID may be unavailable; on
// Windows there is no UID or GID). SID is the Windows user SID ("S-1-5-21-..."), empty elsewhere. User is the account
// name of the caller (the Windows account "DOMAIN\name", or the Unix user resolved from UID), empty when it cannot be
// resolved.
//
// On Windows SID is empty when the token of the caller cannot be read. Admin is set on Windows when that token has the
// BUILTIN\Administrators group enabled: a member of the group running with a UAC-filtered token (the group is "deny
// only" there) is not an administrator for this purpose. It is always false elsewhere.
type Cred struct {
	UID   int
	GID   int
	PID   int
	SID   string
	User  string
	Admin bool
}

// Principal returns the identity of the caller as one string: the decimal uid on Unix, the SID on Windows. It is
// empty when the platform could not tell who the caller is.
func (c Cred) Principal() string {
	if c.UID >= 0 {
		return strconv.Itoa(c.UID)
	}
	return c.SID
}

// PeerCred returns the credentials of the peer of c: SO_PEERCRED on Linux, LOCAL_PEERCRED and LOCAL_PEERPID on
// macOS, GetNamedPipeClientProcessId and the client process token on Windows. The second result is false when c
// is not a connection of the local API listener or the platform has no peer credentials.
func PeerCred(c net.Conn) (Cred, bool) {
	cred, ok := peerCred(c)
	if ok && cred.User == "" && cred.UID >= 0 {
		cred.User = unixUserName(cred.UID)
	}
	return cred, ok
}

const maxUserCache = 1024

// userNames caches uid -> user name lookups (a lookup reads /etc/passwd or asks the directory service).
var userNames struct {
	mu sync.Mutex
	m  map[int]string
}

func unixUserName(uid int) string {
	userNames.mu.Lock()
	name, ok := userNames.m[uid]
	userNames.mu.Unlock()
	if ok {
		return name
	}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		name = u.Username
	}
	userNames.mu.Lock()
	if userNames.m == nil {
		userNames.m = make(map[int]string)
	}
	if len(userNames.m) < maxUserCache {
		userNames.m[uid] = name
	}
	userNames.mu.Unlock()
	return name
}

type credKey struct{}

// ConnContext is an http.Server.ConnContext function that stores the peer credentials of the connection in the
// context. [Serve] installs it; handlers read the result with [PeerCredFromContext].
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if cred, ok := PeerCred(c); ok {
		return context.WithValue(ctx, credKey{}, cred)
	}
	return ctx
}

// WithPeerCred returns a context that carries cred as the peer credentials, as [ConnContext] would store them. It
// is meant for embedders and tests that call a [Backend] directly.
func WithPeerCred(ctx context.Context, cred Cred) context.Context {
	return context.WithValue(ctx, credKey{}, cred)
}

// PeerCredFromContext returns the credentials stored by [ConnContext].
func PeerCredFromContext(ctx context.Context) (Cred, bool) {
	cred, ok := ctx.Value(credKey{}).(Cred)
	return cred, ok
}

// peerAttrs returns slog key/values describing the caller of a request, for audit-style logging. Fields the
// platform does not provide (UID and GID are -1 on Windows, SID and User are empty on Unix without a name) are left out.
func peerAttrs(ctx context.Context) []any {
	cred, ok := PeerCredFromContext(ctx)
	if !ok {
		return nil
	}
	attrs := make([]any, 0, 10)
	if cred.UID >= 0 {
		attrs = append(attrs, "peer_uid", cred.UID)
	}
	if cred.GID >= 0 {
		attrs = append(attrs, "peer_gid", cred.GID)
	}
	attrs = append(attrs, "peer_pid", cred.PID)
	if cred.User != "" {
		attrs = append(attrs, "peer_user", cred.User)
	}
	if cred.SID != "" {
		attrs = append(attrs, "peer_sid", cred.SID)
	}
	return attrs
}
