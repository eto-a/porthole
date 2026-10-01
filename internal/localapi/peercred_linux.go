// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerCred(c net.Conn) (Cred, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Cred{}, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{}, false
	}
	var (
		ucred *unix.Ucred
		serr  error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || serr != nil || ucred == nil {
		return Cred{}, false
	}
	return Cred{UID: int(ucred.Uid), GID: int(ucred.Gid), PID: int(ucred.Pid)}, true
}
