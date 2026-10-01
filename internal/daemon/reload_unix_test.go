// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package daemon

import (
	"syscall"
	"testing"

	"github.com/eto-a/porthole/internal/localapi"
)

func TestSIGHUPReloadsTheFile(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\n")

	h.writeFile("version: 1\ntunnels:\n  blog: {type: http, addr: 3000}\n")
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "blog to appear after SIGHUP", func() bool { return h.tunnels()["blog"].State == localapi.TunnelReady })

	// A broken file on SIGHUP keeps the set.
	h.writeFile("{{{")
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if _, err := h.cl.Reload(t.Context()); err == nil {
		t.Error("the broken file was accepted")
	}
	if h.tunnels()["blog"].State != localapi.TunnelReady {
		t.Error("the set changed after a broken reload")
	}
}
