// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localapi

import (
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/windows"
)

// peerCred identifies the client of a named pipe connection. The identity is used for authorization (the daemon
// trusts only an owner or an administrator), so it is taken from the token of the client as the pipe itself reports it
// (pipeClientIdentity), not from the token of the process whose PID GetNamedPipeClientProcessId returns: a PID can be
// reused between connect and lookup (the client hands the pipe handle to a child and exits, a privileged process
// takes the PID), and the lookup would then classify an unprivileged peer as the new owner of the PID. The PID is
// kept for logging only. If the token cannot be obtained (the client allows no impersonation, nothing has been read
// from the pipe yet), the PID is still reported and SID and User are empty: an unprivileged pipe peer, see
// [buildPipeCred].
func peerCred(c net.Conn) (Cred, bool) {
	h, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return Cred{}, false
	}
	handle := windows.Handle(h.Fd())
	var pid uint32
	pidErr := windows.GetNamedPipeClientProcessId(handle, &pid)
	return buildPipeCred(pid, pidErr, func() (*windows.SID, bool, error) { return pipeClientIdentity(handle) })
}

// buildPipeCred makes the credentials of a pipe client from the result of GetNamedPipeClientProcessId and a function
// that reads the identity of the client. It fails closed: a client whose PID or token cannot be read is still a pipe
// client, reported with no SID and not an administrator (the daemon treats it as unprivileged), never as "no
// credentials", which the daemon would read as "not from a socket, trusted".
func buildPipeCred(pid uint32, pidErr error, identity func() (sid *windows.SID, admin bool, err error)) (Cred, bool) {
	if pidErr != nil || pid == 0 {
		return Cred{UID: -1, GID: -1, PID: -1}, true
	}
	cred := Cred{UID: -1, GID: -1, PID: int(pid)}
	if sid, admin, err := identity(); err == nil {
		cred.SID = sid.String()
		cred.User = accountName(sid)
		cred.Admin = admin
	}
	return cred, true
}

// pipeClientIdentity returns the user SID of the client of the pipe handle and whether its token is that of an
// administrator. It impersonates the client on a locked OS thread, opens the thread token and reverts. The client
// dials with at least identification level (see dialPipeRaw), which is enough to query the token; the token is
// opened as the process (openAsSelf), because at identification level the access check of the thread itself would
// fail. ImpersonateNamedPipeClient fails with ERROR_CANNOT_IMPERSONATE until the server has read from the pipe.
//
// If RevertToSelf fails the thread is deliberately left locked: the goroutine then exits with the thread still
// locked, which makes the runtime terminate the thread instead of returning it to the pool with the client's
// token on it.
func pipeClientIdentity(pipe windows.Handle) (*windows.SID, bool, error) {
	runtime.LockOSThread()
	if err := impersonateNamedPipeClient(pipe); err != nil {
		runtime.UnlockOSThread()
		return nil, false, fmt.Errorf("impersonating the pipe client: %w", err)
	}
	var tok windows.Token
	openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if err := windows.RevertToSelf(); err != nil {
		if openErr == nil {
			_ = tok.Close()
		}
		// Keep the thread locked (see above) and fail closed.
		return nil, false, fmt.Errorf("reverting the impersonation of the pipe client (the thread is abandoned): %w", err)
	}
	runtime.UnlockOSThread()
	if openErr != nil {
		return nil, false, fmt.Errorf("opening the token of the pipe client: %w", openErr)
	}
	defer func() { _ = tok.Close() }()
	return tokenIdentity(tok)
}

// procImpersonateNamedPipeClient is advapi32!ImpersonateNamedPipeClient, which golang.org/x/sys/windows does not wrap.
var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func impersonateNamedPipeClient(pipe windows.Handle) error {
	r, _, e := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return e
	}
	return nil
}

// tokenIdentity returns the user SID of tok and whether tok is that of an administrator.
func tokenIdentity(tok windows.Token) (*windows.SID, bool, error) {
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, false, fmt.Errorf("reading the token user: %w", err)
	}
	// If the groups cannot be read the SID is still known and the client is not an administrator (tokenIsAdmin
	// returns false with the error).
	admin, _ := tokenIsAdmin(tok)
	return tu.User.Sid, admin, nil
}

// tokenIsAdmin reports whether the BUILTIN\Administrators group is enabled in tok. CheckTokenMembership would need an
// impersonation token; reading the groups works on the primary token of another process and gives the same answer:
// the group of a filtered (non-elevated) token has SE_GROUP_USE_FOR_DENY_ONLY and no SE_GROUP_ENABLED.
func tokenIsAdmin(tok windows.Token) (bool, error) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("building the Administrators SID: %w", err)
	}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return false, fmt.Errorf("reading the token groups: %w", err)
	}
	for _, g := range groups.AllGroups() {
		if !g.Sid.Equals(admins) {
			continue
		}
		return g.Attributes&windows.SE_GROUP_ENABLED != 0 && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0, nil
	}
	return false, nil
}

// CurrentSID returns the user SID of this process ("" if it cannot be read).
func CurrentSID() string {
	sid, err := currentUserSID()
	if err != nil {
		return ""
	}
	return sid.String()
}

// accountName returns "DOMAIN\name" for sid, or "" if it cannot be resolved.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
