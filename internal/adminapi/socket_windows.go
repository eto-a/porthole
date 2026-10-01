// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package adminapi

import (
	"context"
	"errors"
	"net"
)

// SocketSupported reports whether this platform serves the admin unix socket.
const SocketSupported = false

// ListenUnix is not available on Windows: the admin API is reachable there only through the bearer endpoint.
func ListenUnix(context.Context, string) (net.Listener, error) {
	return nil, errors.New("adminapi: the admin socket is not supported on windows")
}
