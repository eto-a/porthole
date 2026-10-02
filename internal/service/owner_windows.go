// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// A file that an elevated administrator writes (login --system, the tunnels file of service install, an edit in
// Notepad) is owned by that user's own SID, not by Administrators: Windows' default "object creator" ownership. That
// SID is not trusted, even though the user is an administrator: the owner may rewrite the file's ACL, and so may every
// process of that user that is not elevated, which would turn any of them into SYSTEM. Such files are therefore
// handed to Administrators right after they are written.

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

// secureCopy hands the copy of the binary to Administrators, like every file porthole writes into its system
// directory, so that the service's own check of the directory accepts it.
func secureCopy(path string) error { return SetAdminOwner(path) }
