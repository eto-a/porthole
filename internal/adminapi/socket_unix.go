// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// SocketSupported reports whether this platform serves the admin unix socket.
const SocketSupported = true

// ListenUnix creates the admin socket at path with mode 0600, replacing a stale socket file left by a crashed
// process. It refuses to replace a live socket or a file that is not a socket.
//
// The socket is bound inside a private staging directory (mode 0700, created next to path), chmod-ed to 0600 and
// only then renamed to path. So it is unreachable for other users until its mode is final, and the process-wide
// umask is never touched: a umask change would race with every file or directory that another goroutine (the SSH
// gateway, the ACME cache, the log) creates meanwhile. Docker's go-connections tightens the umask instead; that is
// safe only before any other goroutine runs (idea only, no code copied).
func ListenUnix(ctx context.Context, path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("adminapi: create socket directory: %w", err)
	}
	if err := clearStale(ctx, path); err != nil {
		return nil, err
	}
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("adminapi: %w", err)
	}
	// A short name: unix socket paths are capped at 104 bytes on macOS and 108 on Linux.
	stage := filepath.Join(dir, ".ph"+hex.EncodeToString(rnd[:]))
	if err := os.Mkdir(stage, 0o700); err != nil {
		return nil, fmt.Errorf("adminapi: create staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	tmp := filepath.Join(stage, "s")
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", tmp)
	if err != nil {
		return nil, fmt.Errorf("adminapi: listen on %s: %w", path, err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false) // it would unlink the staging name; the wrapper removes the final one
	fail := func(format string, err error) (net.Listener, error) {
		_ = ln.Close()
		return nil, fmt.Errorf(format, path, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fail("adminapi: chmod %s: %w", err)
	}
	if fi, err := os.Lstat(tmp); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		if err == nil {
			err = fmt.Errorf("mode is %v, want a socket with 0600", fi.Mode())
		}
		return fail("adminapi: socket %s: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail("adminapi: move socket to %s: %w", err)
	}
	return &socketListener{UnixListener: ul, path: path}, nil
}

// socketListener removes the socket file when it is closed, as net.UnixListener does for a socket it created itself.
type socketListener struct {
	*net.UnixListener
	path string
}

func (l *socketListener) Close() error {
	err := l.UnixListener.Close()
	if fi, serr := os.Lstat(l.path); serr == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(l.path)
	}
	return err
}

func clearStale(ctx context.Context, path string) error {
	fi, err := os.Lstat(path) //nolint:gosec // the path is the operator's admin_socket setting
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("adminapi: %w", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("adminapi: %s exists and is not a socket", path)
	}
	d := net.Dialer{Timeout: time.Second}
	if c, err := d.DialContext(ctx, "unix", path); err == nil {
		_ = c.Close()
		return fmt.Errorf("adminapi: %s is in use by another process", path)
	}
	if err := os.Remove(path); err != nil { //nolint:gosec // only a stale socket (checked above) at the operator's admin_socket path
		return fmt.Errorf("adminapi: remove stale socket: %w", err)
	}
	return nil
}
