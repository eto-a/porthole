// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// A file that an elevated administrator writes (login --system, the tunnels file of service install, an edit in
// Notepad) is owned by that user's own SID, not by Administrators: Windows' default "object creator" ownership. The
// user is an administrator, so the file is safe, but the service, which runs as SYSTEM and checks its directory
// before it opens its log, cannot tell that user from anybody else. Such files are therefore handed to Administrators
// right after they are written, and an install run by an elevated administrator accepts that administrator as an
// owner (and then re-owns the file).

// SetAdminOwner makes the built-in Administrators group the owner of path. An elevated administrator may do that:
// the group carries SE_GROUP_OWNER in an elevated token.
func SetAdminOwner(path string) error {
	ba, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, ba, nil, nil, nil); err != nil {
		return fmt.Errorf("make Administrators the owner of %s: %w", path, err)
	}
	return nil
}

// installerTrust is adminTrust plus the user running the command, when that user is an elevated administrator.
func installerTrust() sidTrust {
	if !Elevated() {
		return adminTrust
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return adminTrust
	}
	self := tu.User.Sid.String()
	return func(sid *windows.SID) bool {
		return adminTrust(sid) || (sid != nil && sid.String() == self)
	}
}
