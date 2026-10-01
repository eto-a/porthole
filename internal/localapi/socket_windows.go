// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localapi

import "fmt"

func systemSocketPath() string { return protectedPrefix + "porthole" }

// platformUserSocketPath returns the pipe of the current user, \\.\pipe\porthole-<SID>, or "" if the SID of the
// process cannot be determined. The SID makes the name unique per user on a shared machine (several users, RDP,
// terminal servers).
func platformUserSocketPath() string {
	sid, err := currentUserSID()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%sporthole-%s", pipePrefix, sid)
}
