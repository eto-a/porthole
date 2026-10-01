// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adminapi

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketEndToEnd(t *testing.T) {
	e := newEnv(t, nil)
	path := filepath.Join(t.TempDir(), "sub", "admin.sock")
	ln, err := ListenUnix(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: e.api.SocketHandler(), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket mode %v, want a socket with 0600", fi.Mode())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := NewSocketClient(path).Status(ctx)
	if err != nil || st.Version != "v-test" || st.Clients != 2 {
		t.Fatalf("status %+v, %v", st, err)
	}
}

func TestListenUnixStale(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// A leftover socket file with nobody listening is replaced.
	path := filepath.Join(dir, "stale.sock")
	ln, err := ListenUnix(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// Closing a unix listener removes the file; recreate a stale one by listening and abandoning the descriptor.
	stale := path + ".keep"
	if err := os.Rename(path, stale); err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if err := os.Rename(stale, path); err != nil {
		t.Fatal(err)
	}
	ln2, err := ListenUnix(ctx, path)
	if err != nil {
		t.Fatalf("stale socket was not replaced: %v", err)
	}

	// A live socket is not replaced.
	if _, err := ListenUnix(ctx, path); err == nil {
		t.Error("took over a live socket")
	}
	_ = ln2.Close()

	// A regular file is never removed.
	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(ctx, reg); err == nil {
		t.Error("replaced a regular file")
	}
	if _, err := os.Stat(reg); err != nil {
		t.Errorf("regular file is gone: %v", err)
	}
}
