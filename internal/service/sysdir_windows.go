// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
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
	if err := prepareProtectedDir(dir, systemDirSDDL, adminTrust); err != nil {
		return "", err
	}
	// A logs\ that was there is part of the verified tree; a missing one is made with the protected descriptor too
	// (not left to inheritance, which an existing parent with another DACL would not give).
	if err := prepareProtectedDir(filepath.Join(dir, "logs"), systemDirSDDL, adminTrust); err != nil {
		return "", fmt.Errorf("create the log directory: %w", err)
	}
	return dir, nil
}

// prepareProtectedDir makes sure dir exists and can be trusted by a service that runs as SYSTEM.
//
// A directory that is not there is created with sddl as its security descriptor in the creating call itself, so that
// it is never visible with weaker permissions. A directory that is already there is not adopted: %ProgramData% lets
// every user create folders, so a standard user can plant porthole\ (owned by them, or with a link or a file of
// theirs inside) before the administrator installs the service. It is accepted only if it and everything in it is
// owned by an administrator-class principal, has no access entry for anyone else and contains no link; otherwise the
// error says how to proceed. Nothing is changed in a refused directory.
func prepareProtectedDir(dir, sddl string, trusted sidTrust) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
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
	created := false
	fi, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		p, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return err
		}
		sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(*sa))
		switch err := windows.CreateDirectory(p, sa); {
		case err == nil:
			created = true
		case !errors.Is(err, windows.ERROR_ALREADY_EXISTS):
			return fmt.Errorf("create %s: %w", dir, err)
		}
	case err != nil:
		return fmt.Errorf("check %s: %w", dir, err)
	case !fi.IsDir() || isReparse(fi):
		return unsafeDirError(dir, &UnsafePathError{dir, "is not a plain directory"})
	}
	if created {
		// The directory is ours and empty: set the descriptor once more, in case the creating call dropped the owner.
		err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			owner, nil, dacl, nil)
		if err != nil {
			return fmt.Errorf("set the permissions of %s: %w", dir, err)
		}
	}
	// Also on a directory that was just created: somebody may have won the race between the check and the creation.
	if err := verifyProtectedTree(dir, trusted); err != nil {
		return unsafeDirError(dir, err)
	}
	return nil
}

func unsafeDirError(dir string, err error) error {
	return fmt.Errorf("%s was not made by porthole or an administrator and cannot be trusted (%w). Inspect it, delete it "+
		"(rd /s /q \"%s\" from an elevated terminal) and run this command again", dir, err, dir)
}

// prepareInstallDirWindows returns %ProgramData%\porthole\bin, made like logs\: with the protected descriptor, or
// verified if it was there.
func prepareInstallDirWindows() (string, error) {
	dir, err := prepareSystemDirWindows()
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "bin")
	if err := prepareProtectedDir(bin, systemDirSDDL, adminTrust); err != nil {
		return "", fmt.Errorf("create the binary directory: %w", err)
	}
	return bin, nil
}
