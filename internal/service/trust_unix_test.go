// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package service

import (
	"os"
	"path/filepath"
	"testing"
)

// The real file system with the current user standing in for root.
func TestCheckTreeUnixRealFiles(t *testing.T) {
	me := uint32(os.Getuid())
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil { // not the umask's business
		t.Fatal(err)
	}
	f := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkTreeUnix(root, lstatMeta, me, trustedGroup); err != nil {
		t.Fatalf("a clean tree: %v", err)
	}
	if err := checkTreeUnix(root, lstatMeta, me+1, trustedGroup); err == nil {
		t.Error("a tree of another owner was accepted")
	}
	if err := os.Chmod(f, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := checkTreeUnix(root, lstatMeta, me, trustedGroup); err == nil {
		t.Error("a world-writable file was accepted")
	}
	if err := os.Chmod(f, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := checkTreeUnix(root, lstatMeta, me, trustedGroup); err == nil {
		t.Error("a symbolic link inside the tree was accepted")
	}
}

func TestCheckTrustedPathRealFiles(t *testing.T) {
	f := filepath.Join(t.TempDir(), "porthole")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		t.Skip("root owns everything here; the test needs an unprivileged user")
	}
	// Owned by an unprivileged user: not a binary for a root service.
	if err := CheckTrustedPath(f); err == nil {
		t.Error("a file of an unprivileged user was accepted")
	}
	// A system binary is fine on Linux and macOS.
	if err := CheckTrustedPath("/bin/sh"); err != nil {
		t.Errorf("/bin/sh: %v", err)
	}
}
