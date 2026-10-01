// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestListenCreatesDirAndSocket(t *testing.T) {
	root := shortDir(t)
	dir := filepath.Join(root, "sub", "ph")
	sock := filepath.Join(dir, "s.sock")
	ln, err := Listen(sock, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Fatalf("socket directory not created: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Errorf("created directory mode = %o, want 700", perm)
		}
		si, err := os.Stat(sock)
		if err != nil {
			t.Fatal(err)
		}
		if perm := si.Mode().Perm(); perm != 0o660 {
			t.Errorf("socket mode = %o, want 660", perm)
		}
	}
}

func TestListenKeepsExistingDirMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory modes are not meaningful on Windows")
	}
	dir := shortDir(t)
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(filepath.Join(dir, "s.sock"), 0o660)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o750 {
		t.Errorf("existing directory mode changed to %o, want 750", perm)
	}
}

func TestListenAlreadyRunning(t *testing.T) {
	sock := filepath.Join(shortDir(t), "s.sock")
	ln, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the first listener answering connections like a live daemon.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	defer func() { _ = ln.Close() }()

	ln2, err := Listen(sock, 0o600)
	if !errors.Is(err, ErrAlreadyRunning) {
		if ln2 != nil {
			_ = ln2.Close()
		}
		t.Fatalf("second Listen = %v, want ErrAlreadyRunning", err)
	}
	// The live socket must still work.
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("first listener broken by the second Listen: %v", err)
	}
	_ = c.Close()
}

func TestListenRemovesStaleSocket(t *testing.T) {
	sock := filepath.Join(shortDir(t), "s.sock")
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false) // leave the file behind, as a crashed daemon would
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("stale socket file not left behind: %v", err)
	}

	ln, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestListenRefusesNonSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("socket files are reparse points on Windows; the type check is skipped there")
	}
	path := filepath.Join(shortDir(t), "s.sock")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen(path, 0o600); err == nil {
		_ = ln.Close()
		t.Fatal("Listen over a regular file succeeded")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "precious" {
		t.Errorf("regular file was touched: %q, %v", data, err)
	}
}

func TestListenPathTooLong(t *testing.T) {
	long := filepath.Join(shortDir(t), strings.Repeat("x", 120), "s.sock")
	ln, err := Listen(long, 0o600)
	if err == nil {
		_ = ln.Close()
		t.Fatal("expected an error for an overlong path")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error %q does not mention the limit", err)
	}
	if _, statErr := os.Stat(filepath.Dir(long)); statErr == nil {
		t.Error("directory was created although the path is too long")
	}
	if _, err := Listen("", 0o600); err == nil {
		t.Error("empty path accepted")
	}
}

func TestMaxSocketPath(t *testing.T) {
	for goos, want := range map[string]int{"linux": 107, "darwin": 103, "windows": 107, "freebsd": 103} {
		if got := maxSocketPath(goos); got != want {
			t.Errorf("maxSocketPath(%s) = %d, want %d", goos, got, want)
		}
	}
}

func TestUserSocketPath(t *testing.T) {
	cacheOK := func() (string, error) { return filepath.Join("home", "u", "cache"), nil }
	cacheErr := func() (string, error) { return "", errors.New("no home") }
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	if got, want := userSocketPath("linux", env(map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}), cacheOK), "/run/user/1000/porthole/porthole.sock"; got != want {
		t.Errorf("linux with XDG_RUNTIME_DIR = %q, want %q", got, want)
	}
	cacheWant := filepath.Join("home", "u", "cache", "porthole", "porthole.sock")
	if got := userSocketPath("linux", env(nil), cacheOK); got != cacheWant {
		t.Errorf("linux without XDG_RUNTIME_DIR = %q, want %q", got, cacheWant)
	}
	if got := userSocketPath("linux", env(map[string]string{"XDG_RUNTIME_DIR": "relative"}), cacheOK); got != cacheWant {
		t.Errorf("linux with relative XDG_RUNTIME_DIR = %q, want fallback %q", got, cacheWant)
	}
	for _, goos := range []string{"darwin", "windows"} {
		if got := userSocketPath(goos, env(map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}), cacheOK); got != cacheWant {
			t.Errorf("%s = %q, want %q (XDG_RUNTIME_DIR is ignored)", goos, got, cacheWant)
		}
	}
	if got := userSocketPath("linux", env(nil), cacheErr); got != "" {
		t.Errorf("no home = %q, want empty", got)
	}
}

func TestDefaultSocketPaths(t *testing.T) {
	paths := DefaultSocketPaths()
	if p := UserSocketPath(); p != "" {
		if len(paths) == 0 || paths[0] != p {
			t.Errorf("DefaultSocketPaths = %v, want the user socket %q first", paths, p)
		}
	}
	last := ""
	if len(paths) > 0 {
		last = paths[len(paths)-1]
	}
	if last != SystemSocketPath {
		t.Errorf("DefaultSocketPaths = %v, want the system endpoint last", paths)
	}
	want := map[string]string{
		"linux":   "/run/porthole/porthole.sock",
		"darwin":  "/var/run/porthole/porthole.sock",
		"windows": `\\.\pipe\ProtectedPrefix\Administrators\porthole`,
	}
	if w, ok := want[runtime.GOOS]; ok && SystemSocketPath != w {
		t.Errorf("SystemSocketPath = %q, want %q", SystemSocketPath, w)
	}
}

func TestIsPipePath(t *testing.T) {
	for path, want := range map[string]bool{
		`\\.\pipe\porthole`:                   true,
		`\\.\PIPE\ProtectedPrefix\x\porthole`: true,
		`\\.\pipe\`:                           false,
		`\\.\pipe`:                            false,
		`/run/porthole/porthole.sock`:         false,
		`C:\Users\x\porthole.sock`:            false,
		``:                                    false,
	} {
		if got := IsPipePath(path); got != want {
			t.Errorf("IsPipePath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestPeerAttrs(t *testing.T) {
	if got := peerAttrs(t.Context()); got != nil {
		t.Errorf("peerAttrs without credentials = %v, want nil", got)
	}
	ctx := WithPeerCred(t.Context(), Cred{UID: 1000, GID: 100, PID: 42, User: "alice"})
	if got := fmt.Sprint(peerAttrs(ctx)); got != "[peer_uid 1000 peer_gid 100 peer_pid 42 peer_user alice]" {
		t.Errorf("peerAttrs = %s", got)
	}
	ctx = WithPeerCred(t.Context(), Cred{UID: -1, GID: -1, PID: 7, SID: "S-1-5-21-1", User: `PC\bob`})
	if got := fmt.Sprint(peerAttrs(ctx)); got != `[peer_pid 7 peer_user PC\bob peer_sid S-1-5-21-1]` {
		t.Errorf("peerAttrs = %s", got)
	}
}
