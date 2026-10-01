// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// A socket path nobody listens on is "unavailable" on every OS. On Windows the AF_UNIX dial of a missing path fails
// with WSAEHOSTUNREACH ("A socket operation was attempted to an unreachable host"), not ENOENT (found live with
// v0.3.0-alpha.2: `porthole http 3000` without a daemon reported a daemon that "does not answer properly").
func TestMissingSocketIsUnavailable(t *testing.T) {
	for name, sock := range map[string]string{
		"missing file":             filepath.Join(t.TempDir(), "porthole.sock"),
		"missing directory":        filepath.Join(t.TempDir(), "no", "such", "porthole.sock"),
		"deeper missing directory": filepath.Join(t.TempDir(), "no", "such", "dir", "porthole.sock"),
	} {
		t.Run(name, func(t *testing.T) { checkMissingSocket(t, sock) })
	}
}

func checkMissingSocket(t *testing.T, sock string) {
	t.Helper()
	c := NewClient(sock)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.Status(ctx)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsUnavailable(err) {
		t.Errorf("IsUnavailable(%v) = false, want true", err)
	}
	if IsPermissionDenied(err) {
		t.Errorf("IsPermissionDenied(%v) = true", err)
	}
}

func TestWinsockUnreachableIsUnavailable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Winsock error numbers mean something on Windows only")
	}
	for _, n := range []syscall.Errno{wsaECONNREFUSED, wsaEHOSTUNREACH, wsaENETUNREACH, wsaENETDOWN, wsaEINVAL, syscall.EINVAL} {
		err := fmt.Errorf("localapi: GET /v1/status: dial unix x.sock: connect: %w", n)
		if !IsUnavailable(err) {
			t.Errorf("IsUnavailable(%d) = false", n)
		}
	}
	if IsUnavailable(fmt.Errorf("x: %w", syscall.Errno(wsaEACCES))) {
		t.Error("access denied is not unavailable")
	}
}

func TestWindowsUserEndpointIsNeverASocketFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	for _, p := range DefaultSocketPaths() {
		if !IsPipePath(p) {
			t.Errorf("default endpoint %q is not a named pipe", p)
		}
	}
}
