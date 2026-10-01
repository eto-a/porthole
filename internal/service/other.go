// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package service

import (
	"context"
	"fmt"
	"runtime"
)

func newSCM(bool) (Manager, error) {
	return nil, fmt.Errorf("the Windows service manager on %s: %w", runtime.GOOS, ErrUnsupported)
}

func prepareSystemDirWindows() (string, error) {
	return "", fmt.Errorf("%%ProgramData%% on %s: %w", runtime.GOOS, ErrUnsupported)
}

// IsService reports whether the process was started by the Windows service control manager. It is always false here.
func IsService() (bool, error) { return false, nil }

// RunService runs run under the Windows service control manager; see the Windows implementation. Here it only
// returns [ErrUnsupported].
func RunService(string, func(ctx context.Context, ready func(), reload <-chan struct{}) error) error {
	return fmt.Errorf("running as a Windows service on %s: %w", runtime.GOOS, ErrUnsupported)
}
