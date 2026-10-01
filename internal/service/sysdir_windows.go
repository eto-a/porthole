// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemDirSDDL is the descriptor of %ProgramData%\porthole (ADR 0006 section 3): owned by Administrators, a
// protected DACL (it inherits nothing from %ProgramData%, where Users may create files) that gives SYSTEM and
// Administrators full control, inherited by the files and directories below. The shape is cloudflared's descriptor
// of its token file, made inheritable.
const systemDirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func prepareSystemDirWindows() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("find %%ProgramData%%: %w", err)
	}
	dir := filepath.Join(base, "porthole")
	if err := prepareProtectedDir(dir); err != nil {
		return "", err
	}
	// logs\ inherits the descriptor of its parent (and SetNamedSecurityInfo on the parent propagates it to an
	// existing one).
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o750); err != nil {
		return "", fmt.Errorf("create the log directory: %w", err)
	}
	return dir, nil
}

// prepareProtectedDir creates dir with systemDirSDDL, atomically when it does not exist, and otherwise resets the
// owner and DACL of the existing one. A symbolic link or junction at dir is refused: someone else made it.
func prepareProtectedDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(systemDirSDDL)
	if err != nil {
		return fmt.Errorf("parse the directory descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		p, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return err
		}
		sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(*sa))
		if err := windows.CreateDirectory(p, sa); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	case err != nil:
		return fmt.Errorf("check %s: %w", dir, err)
	case !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
		return fmt.Errorf("%s exists and is not a plain directory; remove it and run this again", dir)
	}
	// Also on a fresh directory: it closes the gap if someone created it between the check and CreateDirectory.
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("set the permissions of %s: %w", dir, err)
	}
	return nil
}
