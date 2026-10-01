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
	return runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(wsaECONNREFUSED))
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
