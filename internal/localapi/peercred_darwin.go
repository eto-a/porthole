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
		xucred  *unix.Xucred
		pid     = -1
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		fdi := int(fd)
		xucred, credErr = unix.GetsockoptXucred(fdi, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if p, perr := unix.GetsockoptInt(fdi, unix.SOL_LOCAL, unix.LOCAL_PEERPID); perr == nil {
			pid = p
		}
	}); err != nil || credErr != nil || xucred == nil {
		return Cred{}, false
	}
	gid := -1
	if xucred.Ngroups > 0 {
		gid = int(xucred.Groups[0])
	}
	return Cred{UID: int(xucred.Uid), GID: gid, PID: pid}, true
}
