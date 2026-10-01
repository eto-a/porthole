// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Design after tailscale (safesocket/pipe_windows.go, BSD-3-Clause), moby (daemon/listeners/listeners_windows.go,
// Apache-2.0) and ADR 0006; the code is written from scratch.

const (
	// protectedPrefix is the pipe namespace in which only administrators may create pipes.
	protectedPrefix = pipePrefix + `ProtectedPrefix\Administrators\`

	pipeBufferSize = 64 << 10

	// pipeClientAccess is what a client asks for and what --allow grants: FILE_GENERIC_READ|FILE_GENERIC_WRITE
	// without FILE_APPEND_DATA, which on a pipe is FILE_CREATE_PIPE_INSTANCE: the right to create more instances of
	// the pipe, that is to serve other clients' connections.
	pipeClientAccess = (windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE) &^ windows.FILE_APPEND_DATA
)

// isProtectedPipe reports whether path is under \\.\pipe\ProtectedPrefix\Administrators\.
func isProtectedPipe(path string) bool {
	return len(path) > len(protectedPrefix) && strings.EqualFold(path[:len(protectedPrefix)], protectedPrefix)
}

// currentUserSID returns the SID of the user this process runs as.
func currentUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("localapi: getting the SID of the current user: %w", err)
	}
	return tu.User.Sid, nil
}

// systemSDDL is the DACL of the system pipe: SYSTEM and Administrators have full control, every allowed principal
// has client access (see pipeClientAccess). Owner and group are left to the creator.
func systemSDDL(allowSIDs []string) string {
	var b strings.Builder
	b.WriteString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	for _, sid := range allowSIDs {
		fmt.Fprintf(&b, "(A;;0x%x;;;%s)", uint32(pipeClientAccess), sid)
	}
	return b.String()
}

// userSDDL is the security descriptor of a user pipe: owned by sid, and sid is the only principal in the DACL. The
// client checks exactly this (see checkPipeExclusive).
func userSDDL(sid string) string { return fmt.Sprintf("O:%sD:P(A;;GA;;;%s)", sid, sid) }

// resolveAllow turns user or group names and SID strings into SID strings.
func resolveAllow(allow []string) ([]string, error) {
	sids := make([]string, 0, len(allow))
	for _, name := range allow {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errors.New("localapi: empty name in the allow list")
		}
		var sid *windows.SID
		if strings.HasPrefix(strings.ToUpper(name), "S-1-") {
			s, err := windows.StringToSid(name)
			if err != nil {
				return nil, fmt.Errorf("localapi: invalid SID %q: %w", name, err)
			}
			sid = s
		} else {
			s, _, _, err := windows.LookupSID("", name)
			if err != nil {
				return nil, fmt.Errorf("localapi: looking up %q: %w", name, err)
			}
			sid = s
		}
		sids = append(sids, sid.String())
	}
	return sids, nil
}

func listenPipe(path string, allow []string) (net.Listener, error) {
	var sddl string
	if isProtectedPipe(path) {
		sids, err := resolveAllow(allow)
		if err != nil {
			return nil, err
		}
		sddl = systemSDDL(sids)
	} else {
		if len(allow) > 0 {
			return nil, fmt.Errorf("localapi: allow is only supported for pipes under %s: any user could create %s in advance", protectedPrefix, path)
		}
		me, err := currentUserSID()
		if err != nil {
			return nil, err
		}
		sddl = userSDDL(me.String())
	}

	// A pipe has no file to go stale: another daemon is running iff the pipe accepts a connection (or has no free
	// instance because it is busy serving).
	pctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	c, err := dialPipeRaw(pctx, path)
	cancel()
	if err == nil {
		_ = c.Close()
		return nil, ErrAlreadyRunning
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, ErrAlreadyRunning
	}

	ln, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    pipeBufferSize,
		OutputBufferSize:   pipeBufferSize,
	})
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			if isProtectedPipe(path) {
				return nil, fmt.Errorf("localapi: creating pipe %s: %w (only administrators may create pipes under ProtectedPrefix\\Administrators; run elevated or use --socket with another pipe name)", path, err)
			}
			return nil, fmt.Errorf("localapi: creating pipe %s: %w (the pipe exists and is owned by someone else)", path, err)
		}
		return nil, fmt.Errorf("localapi: creating pipe %s: %w", path, err)
	}
	return ln, nil
}

// dialPipeRaw opens the pipe with client access and identification impersonation level (the server may learn who
// the client is but cannot act as it), without verifying the pipe.
func dialPipeRaw(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeAccessImpLevel(ctx, path, uint32(pipeClientAccess), winio.PipeImpLevelIdentification)
}

func dialPipe(ctx context.Context, path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	c, err := dialPipeRaw(ctx, path)
	if err != nil {
		return nil, err
	}
	if !isProtectedPipe(path) {
		if err := checkPipeExclusive(c); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("localapi: %s: %w", path, err)
		}
	}
	return c, nil
}

// checkPipeExclusive returns an error unless the pipe behind c is owned by the current user and its DACL grants
// access to nobody else.
//
// All instances of a pipe name share the security descriptor of the first one, and creating another instance needs
// FILE_CREATE_PIPE_INSTANCE, which the DACL grants. So the server on the other end is the current user's iff the
// pipe was created by the current user (only administrators can set another owner) and nobody else may create
// instances. Checking the owner alone would let another user serve a pipe the current user created with a
// permissive DACL.
func checkPipeExclusive(c net.Conn) error {
	h, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("unexpected pipe connection type %T", c)
	}
	me, err := currentUserSID()
	if err != nil {
		return err
	}
	// pipeClientAccess includes READ_CONTROL, so the descriptor can be read.
	sd, err := windows.GetSecurityInfo(windows.Handle(h.Fd()), windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading the security descriptor of the pipe: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("reading the owner of the pipe: %w", err)
	}
	if owner == nil || !owner.Equals(me) {
		return fmt.Errorf("the pipe is owned by %s, not by the current user %s: refusing to talk to it", owner, me)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("reading the DACL of the pipe: %w", err)
	}
	if dacl == nil {
		return errors.New("the pipe has no DACL, so anybody may serve it: refusing to talk to it")
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("reading the DACL of the pipe: %w", err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sid.Equals(me) {
				return fmt.Errorf("the pipe grants access to %s, not only to the current user %s, so another user could serve it: refusing to talk to it", sid, me)
			}
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny entry cannot let anybody in.
		default:
			return fmt.Errorf("the pipe has an access entry of type %d that is not understood: refusing to talk to it", ace.Header.AceType)
		}
	}
	return nil
}
