// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// peerCred identifies the client of a named pipe connection: GetNamedPipeClientProcessId gives the PID, the user is
// read from the token of that process. The token of the process is used rather than ImpersonateNamedPipeClient:
// impersonation works only after the first read from the pipe (ConnContext runs at accept) and only if the client
// allows it. The PID is taken from the kernel at connect time; a client that exits and whose PID is reused within
// this window can be mis-attributed, which is why access control stays on the pipe DACL and the identity is for the
// audit trail. If the process token cannot be opened (a protected process, no privilege), the PID is still reported
// and SID and User are empty.
func peerCred(c net.Conn) (Cred, bool) {
	h, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return Cred{}, false
	}
	var pid uint32
	pidErr := windows.GetNamedPipeClientProcessId(windows.Handle(h.Fd()), &pid)
	return buildPipeCred(pid, pidErr, processIdentity)
}

// buildPipeCred makes the credentials of a pipe client from the result of GetNamedPipeClientProcessId and a function
// that reads the identity of a process. It fails closed: a client whose PID or token cannot be read is still a pipe
// client, reported with no SID and not an administrator (the daemon treats it as unprivileged), never as "no
// credentials", which the daemon would read as "not from a socket, trusted".
func buildPipeCred(pid uint32, pidErr error, identity func(pid uint32) (sid *windows.SID, admin bool, err error)) (Cred, bool) {
	if pidErr != nil || pid == 0 {
		return Cred{UID: -1, GID: -1, PID: -1}, true
	}
	cred := Cred{UID: -1, GID: -1, PID: int(pid)}
	if sid, admin, err := identity(pid); err == nil {
		cred.SID = sid.String()
		cred.User = accountName(sid)
		cred.Admin = admin
	}
	return cred, true
}

// processIdentity returns the user SID of the token of process pid and whether the token is that of an administrator.
func processIdentity(pid uint32) (*windows.SID, bool, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, false, fmt.Errorf("opening process %d: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(p) }()
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, false, fmt.Errorf("opening the token of process %d: %w", pid, err)
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, false, fmt.Errorf("reading the token of process %d: %w", pid, err)
	}
	admin, err := tokenIsAdmin(tok)
	if err != nil {
		return tu.User.Sid, false, nil // the SID is known, the administrator status is not: not an administrator
	}
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
	sid, _, err := processIdentity(windows.GetCurrentProcessId())
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
