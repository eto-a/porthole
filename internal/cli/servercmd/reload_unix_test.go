// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package servercmd

import (
	"context"
	"log/slog"
	"syscall"
	"testing"
	"time"
)

// TestWatchReloadSIGHUP sends a real SIGHUP to the test process: watchReload must catch it (so the default
// action, terminating the process, does not run) and call reload.
func TestWatchReloadSIGHUP(t *testing.T) {
	called := make(chan struct{}, 1)
	stop := watchReload(context.Background(), slog.New(slog.DiscardHandler), func() error {
		called <- struct{}{}
		return nil
	})
	defer stop()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP did not trigger a reload")
	}
}
