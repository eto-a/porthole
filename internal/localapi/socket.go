// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// SystemSocketPath is the socket of the system daemon (Linux package, systemd RuntimeDirectory=porthole).
const SystemSocketPath = "/run/porthole/porthole.sock"

const (
	userSocketName = "porthole.sock"
	userSocketDir  = "porthole"

	probeTimeout          = 2 * time.Second
	readHeaderTimeout     = 5 * time.Second
	serveIdleTimeout      = 2 * time.Minute
	serveMaxHeaderBytes   = 16 << 10
	serveShutdownGrace    = 5 * time.Second
	defaultSocketDirPerms = 0o700
)

// ErrAlreadyRunning is returned by [Listen] when another process answers on the socket path.
var ErrAlreadyRunning = errors.New("localapi: another porthole daemon is already listening on the socket")

// UserSocketPath returns the per-user socket path, or "" if the user's directories cannot be determined.
//
//   - Linux: $XDG_RUNTIME_DIR/porthole/porthole.sock. If XDG_RUNTIME_DIR is unset (no systemd user session) it falls
//     back to <UserCacheDir>/porthole/porthole.sock (~/.cache/porthole/porthole.sock) rather than a /tmp/porthole-<uid>
//     directory: a directory in the shared /tmp can be pre-created by another user (squatting), a directory under the
//     user's home cannot.
//   - Windows: %LocalAppData%\porthole\porthole.sock (the ACL of the per-user directory is the access control).
//   - macOS: <UserCacheDir>/porthole/porthole.sock (~/Library/Caches/porthole/porthole.sock; short, unlike $TMPDIR).
func UserSocketPath() string {
	return userSocketPath(runtime.GOOS, os.Getenv, os.UserCacheDir)
}

func userSocketPath(goos string, getenv func(string) string, cacheDir func() (string, error)) string {
	if goos == "linux" {
		if d := getenv("XDG_RUNTIME_DIR"); len(d) > 0 && d[0] == '/' {
			return path.Join(d, userSocketDir, userSocketName)
		}
	}
	dir, err := cacheDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, userSocketDir, userSocketName)
}

// DefaultSocketPaths lists where the CLI looks for a daemon: the user socket first, then (on Linux) the system one.
func DefaultSocketPaths() []string {
	var paths []string
	if p := UserSocketPath(); p != "" {
		paths = append(paths, p)
	}
	if runtime.GOOS == "linux" {
		paths = append(paths, SystemSocketPath)
	}
	return paths
}

// maxSocketPath returns the largest usable socket path length in bytes (sun_path less the NUL).
func maxSocketPath(goos string) int {
	switch goos {
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly", "ios":
		return 103 // sun_path is 104 bytes
	default:
		return 107 // sun_path is 108 bytes (Linux, Windows)
	}
}

// Listen creates a unix socket listener at socketPath with the given permission bits.
//
// The parent directory is created with mode 0700 if it does not exist; an existing directory is left untouched (the
// system unit's RuntimeDirectory decides its mode). If the path already exists and something answers on it, Listen
// returns [ErrAlreadyRunning]; a stale socket is removed. The socket is chmod-ed after listening (skipped on
// Windows, where the directory ACL is the access control). Two processes starting at the same moment can still race
// between the probe and the bind; the loser gets [ErrAlreadyRunning] when the bind reports "address in use".
func Listen(socketPath string, mode os.FileMode) (net.Listener, error) {
	if socketPath == "" {
		return nil, errors.New("localapi: empty socket path")
	}
	if n, limit := len(socketPath), maxSocketPath(runtime.GOOS); n > limit {
		return nil, fmt.Errorf("localapi: socket path is %d bytes, the limit on %s is %d: %s", n, runtime.GOOS, limit, socketPath)
	}

	dir := filepath.Dir(socketPath)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, defaultSocketDirPerms); err != nil {
			return nil, fmt.Errorf("localapi: creating socket directory: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("localapi: checking socket directory: %w", err)
	}

	if err := removeStale(socketPath); err != nil {
		return nil, err
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		if isAddrInUse(err) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("localapi: listening on %s: %w", socketPath, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(socketPath, mode); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("localapi: chmod socket: %w", err)
		}
	}
	return ln, nil
}

// removeStale deletes socketPath if it is a socket nobody answers on, and fails if somebody does.
func removeStale(socketPath string) error {
	fi, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("localapi: checking %s: %w", socketPath, err)
	}
	if runtime.GOOS != "windows" && fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("localapi: %s exists and is not a socket", socketPath)
	}
	conn, err := net.DialTimeout("unix", socketPath, probeTimeout)
	if err == nil {
		_ = conn.Close()
		return ErrAlreadyRunning
	}
	if IsPermissionDenied(err) {
		return fmt.Errorf("localapi: probing %s: %w", socketPath, err)
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("localapi: removing stale socket: %w", err)
	}
	return nil
}

func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	return runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(wsaEADDRINUSE))
}

// Serve serves handler on ln until ctx is done, then shuts down gracefully: open event streams are ended (the
// request contexts are cancelled), and connections still busy after a short grace period are closed. It sets header
// and idle timeouts, puts the peer credentials of every connection into the request context (see [ConnContext]) and
// takes ownership of ln. It returns nil after a graceful shutdown.
func Serve(ctx context.Context, ln net.Listener, handler http.Handler, log *slog.Logger) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	base, cancelBase := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelBase()

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       serveIdleTimeout,
		MaxHeaderBytes:    serveMaxHeaderBytes,
		BaseContext:       func(net.Listener) context.Context { return base },
		ConnContext:       ConnContext,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	// No ReadTimeout/WriteTimeout: they would also kill the long-lived event streams and, for reads, break the
	// background read that notices a disconnected client. The handler sets per-operation deadlines instead.
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("localapi: serve: %w", err)
	case <-ctx.Done():
	}

	cancelBase()
	gctx, cancel := context.WithTimeout(context.Background(), serveShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(gctx); err != nil {
		log.Warn("local api graceful shutdown incomplete, closing connections", "err", err)
		_ = srv.Close()
	}
	<-errc
	return nil
}
