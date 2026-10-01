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
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(h.Fd()), &pid); err != nil || pid == 0 {
		return Cred{}, false
	}
	cred := Cred{UID: -1, GID: -1, PID: int(pid)}
	if sid, err := processUserSID(pid); err == nil {
		cred.SID = sid.String()
		cred.User = accountName(sid)
	}
	return cred, true
}

// processUserSID returns the user SID of the token of process pid.
func processUserSID(pid uint32) (*windows.SID, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("opening process %d: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(p) }()
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, fmt.Errorf("opening the token of process %d: %w", pid, err)
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("reading the token of process %d: %w", pid, err)
	}
	return tu.User.Sid, nil
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
