// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"
)

// Winsock error numbers. Go's syscall package does not map them to the portable errors on Windows, so they are
// compared by value (and only when running on Windows, where these numbers mean what they say).
const (
	wsaEACCES       = 10013
	wsaEADDRINUSE   = 10048
	wsaECONNREFUSED = 10061
	wsaEINVAL       = 10022
	wsaENETDOWN     = 10050
	wsaENETUNREACH  = 10051
	wsaEHOSTUNREACH = 10065
)

// IsUnavailable reports whether err means that no daemon is listening on the socket: the socket file does not exist
// or nobody accepts on it. The caller should then run standalone. API errors (*Error) never match.
func IsUnavailable(err error) bool {
	if err == nil || isAPIError(err) {
		return false
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// A socket path longer than the platform limit (104 bytes on macOS, 108 on Linux) fails with EINVAL before any
	// daemon is reached, so nobody can be listening there either.
	if errors.Is(err, syscall.EINVAL) {
		return true
	}
	// On Windows an AF_UNIX dial to a path that does not exist fails with WSAEHOSTUNREACH ("A socket operation was
	// attempted to an unreachable host"), not with ENOENT; for a path whose directory does not exist it is WSAENETDOWN
	// ("dead network"), WSAENETUNREACH or "invalid argument" (a deeper missing path). None of them can come from a
	// daemon that answers, so they mean "nobody there".
	if runtime.GOOS != "windows" {
		return false
	}
	for _, n := range []syscall.Errno{wsaECONNREFUSED, wsaEHOSTUNREACH, wsaENETUNREACH, wsaENETDOWN, wsaEINVAL, syscall.EINVAL} {
		if errors.Is(err, n) {
			return true
		}
	}
	return false
}

// IsPermissionDenied reports whether err means that the socket exists but the caller may not use it (EACCES, or
// access denied on Windows). The caller must not fall back to running standalone then: a second session with the
// same token would replace the daemon's.
func IsPermissionDenied(err error) bool {
	if err == nil || isAPIError(err) {
		return false
	}
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EACCES) {
		return true
	}
	return runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(wsaEACCES))
}

func isAPIError(err error) bool {
	var e *Error
	return errors.As(err, &e)
}
