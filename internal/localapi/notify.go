// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
)

// sd_notify states.
const (
	NotifyReady    = "READY=1"
	NotifyStopping = "STOPPING=1"
)

const notifyTimeout = 5 * time.Second

// Notify sends state (for example [NotifyReady]) to the service manager over $NOTIFY_SOCKET (sd_notify(3)). It
// returns false without an error when $NOTIFY_SOCKET is not set or on Windows, so it is safe to call
// unconditionally. An address starting with '@' is an abstract socket.
func Notify(state string) (bool, error) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" || runtime.GOOS == "windows" {
		return false, nil
	}
	switch addr[0] {
	case '@':
		addr = "\x00" + addr[1:]
	case '/':
	default:
		return false, fmt.Errorf("localapi: unsupported NOTIFY_SOCKET %q: must start with / or @", addr)
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return false, fmt.Errorf("localapi: connecting to NOTIFY_SOCKET: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(notifyTimeout))
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, fmt.Errorf("localapi: writing to NOTIFY_SOCKET: %w", err)
	}
	return true, nil
}
