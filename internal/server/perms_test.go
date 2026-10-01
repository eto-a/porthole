// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// N-11: a data or certificate directory that exists with a loose mode is tightened at startup.
func TestTightenDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(dir, quietLogger()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %04o, want 0700", fi.Mode().Perm())
	}
	// A missing directory is not created by tightenDir (data_dir may be created later by the store).
	missing := filepath.Join(t.TempDir(), "nope")
	tightenDir(missing, quietLogger())
	if _, err := os.Stat(missing); err == nil {
		t.Error("tightenDir created a missing directory")
	}
}
