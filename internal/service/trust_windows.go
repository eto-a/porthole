// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows rules for what a service running as SYSTEM may trust (see trust.go for the reasoning). The question is who
// can change the object, not who can read it: an ACE that lets a principal other than SYSTEM, Administrators or
// TrustedInstaller write, delete or re-permission the file, or delete or replace it through its directory, makes the
// path unsafe. Owners count too, because the owner can always rewrite the DACL.
//
// Deny entries are ignored (an allow entry that a deny entry neutralises is still reported; the cure is
// --allow-unsafe-path or fixing the ACL), and inherit-only entries are ignored where they do not apply to the object
// itself.

const (
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	sidCreatorOwner     = "S-1-3-0"

	aceInheritOnly = 0x08 // INHERIT_ONLY_ACE
	aceObjectInh   = 0x01 // OBJECT_INHERIT_ACE
	aceContainerIn = 0x02 // CONTAINER_INHERIT_ACE

	maximumAllowed  = 0x02000000
	fileDeleteChild = 0x40 // FILE_DELETE_CHILD

	// changeMask: any of these lets a principal modify the object, or a directory's contents.
	changeMask windows.ACCESS_MASK = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES |
		fileDeleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.GENERIC_WRITE | windows.GENERIC_ALL | maximumAllowed
	// replaceMask: what lets a principal replace or rename an object (for a directory high above the file: swap the
	// subtree). Adding files to such a directory does not touch what is already in it.
	replaceMask = fileDeleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.GENERIC_WRITE | windows.GENERIC_ALL | maximumAllowed
)

// sidTrust says whether a principal may be given the keys: it is part of the administration of the machine.
type sidTrust func(*windows.SID) bool

func adminTrust(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if sid.IsWellKnown(wk) {
			return true
		}
	}
	s := sid.String()
	return s == sidTrustedInstaller || s == sidCreatorOwner
}

// aclRole tells which part of the path a descriptor belongs to.
type aclRole int

const (
	roleFile     aclRole = iota // the file the service uses
	roleParent                  // the directory that holds it
	roleAncestor                // a directory further up
	roleTree                    // an entry of a protected directory: no outsider may have any access
)

// checkDescriptor applies the rules to the owner and the DACL of the object at p.
func checkDescriptor(p string, isDir bool, role aclRole, trusted sidTrust) error {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return &UnsafePathError{p, "its permissions cannot be read: " + err.Error()}
	}
	return evalDescriptor(sd, p, isDir, role, trusted)
}

func evalDescriptor(sd *windows.SECURITY_DESCRIPTOR, p string, isDir bool, role aclRole, trusted sidTrust) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return &UnsafePathError{p, "its owner cannot be read"}
	}
	if !trusted(owner) {
		return &UnsafePathError{p, fmt.Sprintf("is owned by %s, who could change its permissions", describeSID(owner))}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return &UnsafePathError{p, "its permissions cannot be read: " + err.Error()}
	}
	if dacl == nil {
		return &UnsafePathError{p, "has no access control list, so every user has full access"}
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return &UnsafePathError{p, "its permissions cannot be read: " + err.Error()}
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return &UnsafePathError{p, fmt.Sprintf("has an access entry of type %d that is not understood", ace.Header.AceType)}
		}
		flags := ace.Header.AceFlags
		if flags&aceInheritOnly != 0 && (!isDir || role != roleTree || flags&(aceObjectInh|aceContainerIn) == 0) {
			continue // does not apply to this object, nor (in a protected directory) to anything created in it
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if trusted(sid) {
			continue
		}
		var mask windows.ACCESS_MASK
		switch role {
		case roleFile, roleParent:
			mask = changeMask
		case roleAncestor:
			mask = replaceMask
		case roleTree:
			mask = 0xFFFFFFFF
		}
		if got := ace.Mask & mask; got != 0 {
			return &UnsafePathError{p, fmt.Sprintf("grants %s access (0x%x) that lets a user other than an administrator change it", describeSID(sid), got)}
		}
	}
	return nil
}

func describeSID(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain != "" {
		account = domain + `\` + account
	}
	return account + " (" + sid.String() + ")"
}

func isReparse(fi fs.FileInfo) bool {
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return true
	}
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// CheckTrustedPath returns an *[UnsafePathError] unless a user who is not an administrator can neither change the
// file at path nor replace it through one of its directories. A path that does not exist yet is judged by its
// closest existing parent. A link (symbolic link, junction) anywhere in the path is refused: where it points can be
// changed by whoever may write the link's directory, which this check would have to follow forever.
func CheckTrustedPath(path string) error { return checkTrustedPath(path, adminTrust) }

func checkTrustedPath(path string, trusted sidTrust) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	next := roleFile // the role of the next existing component on the way up
	for p := filepath.Clean(abs); ; {
		fi, err := os.Lstat(p) //nolint:gosec // p is a path of this very check; nothing is opened or modified
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// not there (yet): its directory protects it
			if next == roleFile {
				next = roleParent
			}
		case err != nil:
			return &UnsafePathError{p, "cannot be examined: " + err.Error()}
		default:
			if isReparse(fi) {
				return &UnsafePathError{p, "is a link; give the real path"}
			}
			role := next
			if fi.IsDir() && role == roleFile {
				role = roleParent
			}
			if err := checkDescriptor(p, fi.IsDir(), role, trusted); err != nil {
				return err
			}
			next = roleAncestor
			if role == roleFile {
				next = roleParent
			}
		}
		up := filepath.Dir(p)
		if up == p {
			return nil
		}
		p = up
	}
}

// VerifyProtectedDir returns an error unless dir and everything in it is owned by SYSTEM, Administrators or
// TrustedInstaller, has no access entry for anybody else and contains no link (reparse point).
func VerifyProtectedDir(dir string) error { return verifyProtectedTree(dir, adminTrust) }

// verifyProtectedTree checks that nothing in the directory root was put there by an ordinary user: the root and
// every entry below it is owned by an administrator-class principal, has no access entry for anyone else, and is not
// a link of any kind.
func verifyProtectedTree(root string, trusted sidTrust) error {
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return &UnsafePathError{p, "cannot be examined: " + err.Error()}
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return &UnsafePathError{p, "cannot be examined: " + err.Error()}
		}
		if isReparse(fi) {
			return &UnsafePathError{p, "is a link (reparse point)"}
		}
		return checkDescriptor(p, fi.IsDir(), roleTree, trusted)
	})
}
