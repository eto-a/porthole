// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package localapi

import (
	"context"
	"errors"
	"net"
	"runtime"
)

// errNoPipes is returned for a named pipe path on an OS other than Windows.
var errNoPipes = errors.New("localapi: named pipes are only supported on Windows")

func systemSocketPath() string {
	if runtime.GOOS == "linux" {
		return "/run/porthole/porthole.sock"
	}
	return "/var/run/porthole/porthole.sock"
}

// platformUserSocketPath returns "": on Unix the per-user path is a socket file, see userSocketPath.
func platformUserSocketPath() string { return "" }

func listenPipe(string, []string) (net.Listener, error) { return nil, errNoPipes }

func dialPipe(context.Context, string) (net.Conn, error) { return nil, errNoPipes }
