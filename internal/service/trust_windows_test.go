// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package service

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEvalDescriptor(t *testing.T) {
	const base = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	cases := []struct {
		name  string
		sddl  string
		dir   bool
		role  aclRole
		allow bool
	}{
		{"administrators and users that read", base + "(A;;0x1200a9;;;BU)", false, roleFile, true},
		{"users may modify", base + "(A;;FRFW;;;BU)", false, roleFile, false},
		{"authenticated users full control", base + "(A;;FA;;;AU)", false, roleFile, false},
		{"everyone full control", base + "(A;;GA;;;WD)", false, roleFile, false},
		{"a user may write", base + "(A;;FW;;;S-1-5-21-1-2-3-1001)", false, roleFile, false},
		{"a user owns it", "O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;SY)(A;;FA;;;BA)", false, roleFile, false},
		{"no DACL", "O:BAD:NO_ACCESS_CONTROL", false, roleFile, false},
		{"inherit-only entry does not apply to a file", base + "(A;OICIIO;FA;;;BU)", false, roleFile, true},
		{"users may add files to the directory of the file", base + "(A;;0x2;;;BU)", true, roleParent, false},
		{"users may add files to a directory higher up", base + "(A;;0x2;;;BU)", true, roleAncestor, true},
		{"users may delete children higher up", base + "(A;;0x40;;;BU)", true, roleAncestor, false},
		{"users may re-permission a directory higher up", base + "(A;;WD;;;BU)", true, roleAncestor, false},
		{"a deny entry is not a grant", base + "(D;;FW;;;BU)", false, roleFile, true},
		{"inheritable entry for users in a protected directory", base + "(A;OICIIO;FR;;;BU)", true, roleTree, false},
		{"read access for users in a protected directory", base + "(A;;FR;;;BU)", false, roleTree, false},
		{"the protected directory as created", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true, roleTree, true},
	}
	for _, c := range cases {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		err = evalDescriptor(sd, `C:\x`, c.dir, c.role, adminTrust)
		var u *UnsafePathError
		switch {
		case c.allow && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case !c.allow && !errors.As(err, &u):
			t.Errorf("%s: accepted (error %v)", c.name, err)
		}
	}
}

func TestCheckTrustedPathSystemFileAndUserFile(t *testing.T) {
	if err := CheckTrustedPath(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")); err != nil {
		t.Errorf("cmd.exe: %v", err)
	}
	// A file in a directory that the current user created is theirs (and, for a standard user, not an administrator's).
	f := filepath.Join(t.TempDir(), "porthole.exe")
	if err := os.WriteFile(f, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	var u *UnsafePathError
	if err := checkTrustedPath(f, adminTrust); !errors.As(err, &u) {
		t.Errorf("a file in the temp directory of a user: error %v, want an unsafe path error", err)
	}
	// Not existing yet: its (user-writable) directory decides.
	if err := checkTrustedPath(filepath.Join(t.TempDir(), "sub", "config.yaml"), adminTrust); !errors.As(err, &u) {
		t.Errorf("a missing file in a user directory: error %v", err)
	}
}

// userTrust trusts what adminTrust trusts and the current user, so that the tests can build trees that the current
// (unprivileged) process owns.
func userTrust(t *testing.T) sidTrust {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return func(s *windows.SID) bool { return adminTrust(s) || s.Equals(tu.User.Sid) }
}

func TestVerifyProtectedTree(t *testing.T) {
	trusted := userTrust(t)
	// The default owner of a new file can be the user or the Administrators group, both trusted here; the DACL of a
	// new file in the temp directory only has entries for the user, SYSTEM and Administrators.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := verifyProtectedTree(root, trusted); err != nil {
		t.Fatalf("a clean tree: %v", err)
	}
	// The same tree is refused when the user is not trusted: it is the user's own.
	var u *UnsafePathError
	if err := verifyProtectedTree(root, adminTrust); !errors.As(err, &u) {
		t.Errorf("a tree of the current user was accepted by the administrator rule: %v", err)
	}

	// A junction (a reparse point that needs no privilege) planted inside.
	target := t.TempDir()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "logs", "evil"), target).CombinedOutput(); err != nil { //nolint:gosec // test helper with paths of its own temp directories
		t.Skipf("cannot make a junction: %v: %s", err, out)
	}
	if err := verifyProtectedTree(root, trusted); !errors.As(err, &u) {
		t.Errorf("a junction inside the tree: error %v", err)
	}
	if err := os.Remove(filepath.Join(root, "logs", "evil")); err != nil {
		t.Fatal(err)
	}
	if err := verifyProtectedTree(root, trusted); err != nil {
		t.Fatalf("after removing the junction: %v", err)
	}

	// An entry for Everyone, as an attacker who pre-created the directory would leave.
	if out, err := exec.Command("icacls", filepath.Join(root, "config.yaml"), "/grant", "*S-1-1-0:R").CombinedOutput(); err != nil { //nolint:gosec // test helper with paths of its own temp directories
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if err := verifyProtectedTree(root, trusted); !errors.As(err, &u) {
		t.Errorf("an entry for Everyone: error %v", err)
	}
}

// userDirSDDL is systemDirSDDL for a test that runs without administrator rights: the current user stands in for
// Administrators.
func userDirSDDL(t *testing.T) string {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := tu.User.Sid.String()
	return "O:" + me + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + me + ")"
}

func TestPrepareProtectedDir(t *testing.T) {
	trusted, sddl := userTrust(t), userDirSDDL(t)
	root := t.TempDir()

	// A new directory is created with the protected descriptor and accepted.
	fresh := filepath.Join(root, "fresh")
	if err := prepareProtectedDir(fresh, sddl, trusted); err != nil {
		t.Fatalf("new directory: %v", err)
	}
	// Running it again (an upgrade) accepts what it made, files included.
	if err := os.WriteFile(filepath.Join(fresh, "config.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareProtectedDir(fresh, sddl, trusted); err != nil {
		t.Fatalf("existing directory of ours: %v", err)
	}

	// A directory that somebody else prepared: here, one that gives Everyone access.
	planted := filepath.Join(root, "planted")
	if err := os.Mkdir(planted, 0o750); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", planted, "/grant", "*S-1-1-0:(OI)(CI)R").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	before, err := windows.GetNamedSecurityInfo(planted, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	err = prepareProtectedDir(planted, sddl, trusted)
	var u *UnsafePathError
	if !errors.As(err, &u) {
		t.Fatalf("a planted directory was adopted: %v", err)
	}
	after, err := windows.GetNamedSecurityInfo(planted, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Errorf("a refused directory was changed:\nbefore %s\nafter  %s", before, after)
	}

	// A file in the place of the directory.
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareProtectedDir(file, sddl, trusted); err == nil {
		t.Error("a file was accepted as the directory")
	}
}
