// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// SocketSupported reports whether this platform serves the admin unix socket.
const SocketSupported = true

// umaskMu serialises the process-wide umask change in ListenUnix.
var umaskMu sync.Mutex

// ListenUnix creates the admin socket at path with mode 0600, replacing a stale socket file left by a crashed
// process. It refuses to replace a live socket or a file that is not a socket.
//
// The umask is tightened around listen(2) so the socket never exists with wider permissions (the same approach as
// Docker's go-connections, Apache-2.0: idea only, no code copied); the explicit chmod covers odd filesystems.
func ListenUnix(ctx context.Context, path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("adminapi: create socket directory: %w", err)
	}
	if err := clearStale(ctx, path); err != nil {
		return nil, err
	}
	umaskMu.Lock()
	old := syscall.Umask(0o177)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	syscall.Umask(old)
	umaskMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("adminapi: listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("adminapi: chmod %s: %w", path, err)
	}
	return ln, nil
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
