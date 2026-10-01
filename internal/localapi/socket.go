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
	"strings"
	"syscall"
	"time"
)

// SystemSocketPath is the endpoint of the system daemon: /run/porthole/porthole.sock on Linux (systemd
// RuntimeDirectory=porthole), /var/run/porthole/porthole.sock on macOS and other Unix systems, and the named pipe
// \\.\pipe\ProtectedPrefix\Administrators\porthole on Windows (only administrators can create pipes under that
// prefix, so no other user can squat the name).
var SystemSocketPath = systemSocketPath()

// pipePrefix starts the path of every Windows named pipe; a path with this prefix is a pipe, anything else is a
// unix socket path.
const pipePrefix = `\\.\pipe\`

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
//   - Windows: the named pipe \\.\pipe\porthole-<SID> of the current user (owner-only DACL, checked by the client).
//   - macOS: <UserCacheDir>/porthole/porthole.sock (~/Library/Caches/porthole/porthole.sock; short, unlike $TMPDIR).
func UserSocketPath() string {
	if p := platformUserSocketPath(); p != "" {
		return p
	}
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

// DefaultSocketPaths lists where the CLI looks for a daemon: the user endpoint first, then the system one.
func DefaultSocketPaths() []string {
	var paths []string
	if p := UserSocketPath(); p != "" {
		paths = append(paths, p)
	}
	return append(paths, SystemSocketPath)
}

// IsPipePath reports whether endpoint names a Windows named pipe (it starts with \\.\pipe\, case-insensitive).
// Any other value is a unix socket path.
func IsPipePath(endpoint string) bool {
	return len(endpoint) > len(pipePrefix) && strings.EqualFold(endpoint[:len(pipePrefix)], pipePrefix)
}

// Dial connects to the daemon endpoint at endpoint: a named pipe (Windows only) or a unix socket. The connect is
// bounded by a timeout. A user pipe is verified before it is returned: it must be owned by the current user and
// grant access to nobody else, because a pipe name outside \\.\pipe\ProtectedPrefix\Administrators can be created
// by any user in advance (squatting).
func Dial(ctx context.Context, endpoint string) (net.Conn, error) {
	if IsPipePath(endpoint) {
		return dialPipe(ctx, endpoint)
	}
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "unix", endpoint)
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

// Listen creates a listener at socketPath with the given permission bits: a unix socket, or on Windows a named
// pipe when socketPath is a pipe path (see [IsPipePath]); a pipe path on another OS is an error. It is
// [ListenAllow] without extra principals.
//
// A named pipe under \\.\pipe\ProtectedPrefix\Administrators (the [SystemSocketPath] on Windows) gets the DACL
// SYSTEM + Administrators, any other pipe is owned by and open only to the current user; creating a system pipe needs
// an elevated process. mode is ignored for pipes, and "already running" means that a connection to the pipe succeeds.
//
// For a unix socket:
//
// The parent directory is created with mode 0700 if it does not exist; an existing directory is left untouched (the
// system unit's RuntimeDirectory decides its mode). If the path already exists and something answers on it, Listen
// returns [ErrAlreadyRunning]; a stale socket is removed. The socket is chmod-ed after listening (skipped on
// Windows, where the directory ACL is the access control). Two processes starting at the same moment can still race
// between the probe and the bind; the loser gets [ErrAlreadyRunning] when the bind reports "address in use".
func Listen(socketPath string, mode os.FileMode) (net.Listener, error) {
	return ListenAllow(socketPath, mode, nil)
}

// ListenAllow is [Listen] that also admits the principals in allow to a system named pipe: user or group names
// (for example "BUILTIN\\Users") or SIDs ("S-1-5-32-545"), each given read and write access without the right to
// create further pipe instances. It is an error to pass allow for a pipe outside ProtectedPrefix\Administrators
// (anybody could squat such a name, so the pipe stays private to its owner). allow is ignored for unix sockets: their
// access control is mode and the directory.
func ListenAllow(socketPath string, mode os.FileMode, allow []string) (net.Listener, error) {
	if socketPath == "" {
		return nil, errors.New("localapi: empty socket path")
	}
	if IsPipePath(socketPath) {
		return listenPipe(socketPath, allow)
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
