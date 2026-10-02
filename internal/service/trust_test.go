// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func fakeStat(m map[string]fileMeta) statFunc {
	return func(p string) (fileMeta, error) {
		if v, ok := m[p]; ok {
			return v, nil
		}
		return fileMeta{}, fs.ErrNotExist
	}
}

func rootDir(mode fs.FileMode) fileMeta { return fileMeta{Mode: fs.ModeDir | mode} }

func TestCheckChainUnix(t *testing.T) {
	good := map[string]fileMeta{
		"/":                       rootDir(0o755),
		"/usr":                    rootDir(0o755),
		"/usr/local":              rootDir(0o755),
		"/usr/local/bin":          rootDir(0o755),
		"/usr/local/bin/porthole": {Mode: 0o755},
	}
	if err := checkChainUnix("/usr/local/bin/porthole", fakeStat(good), 0, trustedGroup); err != nil {
		t.Fatalf("a root-owned chain: %v", err)
	}

	bad := func(mut func(m map[string]fileMeta), wantPath string) {
		t.Helper()
		m := map[string]fileMeta{}
		for k, v := range good {
			m[k] = v
		}
		mut(m)
		err := checkChainUnix("/usr/local/bin/porthole", fakeStat(m), 0, trustedGroup)
		var u *UnsafePathError
		if !errors.As(err, &u) || u.Path != wantPath {
			t.Errorf("error %v, want an unsafe path error for %s", err, wantPath)
		}
	}
	bad(func(m map[string]fileMeta) { m["/usr/local/bin/porthole"] = fileMeta{UID: 501, Mode: 0o755} }, "/usr/local/bin/porthole")
	bad(func(m map[string]fileMeta) { m["/usr/local/bin/porthole"] = fileMeta{Mode: 0o757} }, "/usr/local/bin/porthole")
	bad(func(m map[string]fileMeta) { m["/usr/local"] = fileMeta{UID: 501, Mode: fs.ModeDir | 0o755} }, "/usr/local") // Homebrew-style owner
	bad(func(m map[string]fileMeta) { m["/usr/local/bin"] = fileMeta{GID: 1000, Mode: fs.ModeDir | 0o775} }, "/usr/local/bin")
	bad(func(m map[string]fileMeta) { m["/usr"] = fileMeta{Mode: fs.ModeDir | fs.ModeSticky | 0o777} }, "/usr")

	// Group write for the group of root is accepted, and so is a file that does not exist yet.
	m := map[string]fileMeta{"/": rootDir(0o755), "/etc": {GID: 0, Mode: fs.ModeDir | 0o775}}
	if err := checkChainUnix("/etc/porthole/config.yaml", fakeStat(m), 0, trustedGroup); err != nil {
		t.Errorf("not yet existing file in a root-group directory: %v", err)
	}
	if err := checkChainUnix("relative/path", fakeStat(m), 0, trustedGroup); err == nil {
		t.Error("a relative path was accepted")
	}
}

func TestCheckTreeUnix(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"config.yaml", "tunnels.yaml"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// lstat reports every entry as owned by root, except what the case changes.
	lstatWith := func(special string, m fileMeta) statFunc {
		return func(p string) (fileMeta, error) {
			if filepath.Base(p) == special {
				return m, nil
			}
			return fileMeta{Mode: 0o644}, nil
		}
	}
	if err := checkTreeUnix(root, lstatWith("", fileMeta{}), 0, trustedGroup); err != nil {
		t.Fatalf("a tree of root: %v", err)
	}
	for name, m := range map[string]fileMeta{
		"a file of a user":  {UID: 501, Mode: 0o600},
		"a symbolic link":   {Mode: fs.ModeSymlink | 0o777},
		"a writable file":   {Mode: 0o666},
		"a group-writable":  {GID: 20, Mode: 0o660},
		"a special file":    {Mode: fs.ModeNamedPipe | 0o600},
		"a different owner": {UID: 1, Mode: 0o600},
	} {
		if err := checkTreeUnix(root, lstatWith("config.yaml", m), 0, trustedGroup); err == nil {
			t.Errorf("%s inside the directory was accepted", name)
		}
	}
}

func TestPrepareDarwinDirsRefusesForeignDirectory(t *testing.T) {
	root := t.TempDir()
	cfg, logs := filepath.Join(root, "cfg"), filepath.Join(root, "logs")
	if err := os.MkdirAll(cfg, 0o750); err != nil {
		t.Fatal(err)
	}
	foreign := func(string) (fileMeta, error) { return fileMeta{UID: 501, Mode: fs.ModeDir | 0o750}, nil }
	fr := &fakeRunner{}
	if err := prepareDarwinDirs(context.Background(), fr, foreign, cfg, logs); err == nil {
		t.Fatal("a directory of another user was adopted")
	}
	if len(fr.got()) != 0 {
		t.Errorf("commands ran against a foreign directory: %q", fr.got())
	}
	if _, err := os.Stat(logs); err == nil {
		t.Error("the log directory was created although the configuration directory was refused")
	}
}
