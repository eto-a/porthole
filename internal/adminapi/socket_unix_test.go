// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adminapi

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
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

func TestSocketClientMethods(t *testing.T) {
	e := newEnv(t, map[string][]string{"tok1": {"admin:read"}})
	path := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := ListenUnix(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: e.api.SocketHandler(), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := NewSocketClient(path)

	if cs, err := c.Clients(ctx); err != nil || len(cs) != 1 || cs[0].Name != "home" {
		t.Fatalf("clients %+v, %v", cs, err)
	}
	if ts, err := c.Tunnels(ctx); err != nil || len(ts) != 0 {
		t.Fatalf("tunnels %+v, %v", ts, err)
	}
	if toks, err := c.Tokens(ctx); err != nil || len(toks) != 1 || toks[0].ID != "tok1" {
		t.Fatalf("tokens %+v, %v", toks, err)
	}
	if err := c.Disconnect(ctx, "home"); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	var apiErr *Error
	if err := c.Disconnect(ctx, "ghost"); !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
		t.Fatalf("disconnect ghost: %v", err)
	}
	if err := c.CloseTunnel(ctx, "tun1"); err != nil {
		t.Fatalf("close tunnel: %v", err)
	}
	if err := c.RevokeToken(ctx, "tok1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	es, err := c.Audit(ctx, 2)
	// The fake store lists newest first, like the real one.
	if err != nil || len(es) != 2 || es[0].Action != "token.revoke" || es[0].Actor != ActorSocket || es[1].Action != "tunnel.close" {
		t.Fatalf("audit %+v, %v", es, err)
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

// A11: the socket gets its final mode before it appears at its path, and the process umask is left alone (a umask
// change would race with files created by other goroutines).
func TestListenUnixModeAndUmask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.sock")
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	ln, err := ListenUnix(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got := syscall.Umask(0o022); got != 0o022 {
		t.Errorf("umask is %o after ListenUnix, want it untouched (022)", got)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket = %v, %v; want a socket with mode 0600", fi, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("leftover files next to the socket: %v", entries)
	}
	_ = ln.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket file not removed on Close: %v", err)
	}
}
