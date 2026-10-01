// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

// System directories (ADR 0006 section 3).
const (
	linuxSystemDir  = "/etc/porthole"
	darwinSystemDir = "/Library/Application Support/porthole"
	darwinLogDir    = "/Library/Logs/porthole"
)

// PrepareSystemDir creates the configuration directory of the system service with the permissions of ADR 0006
// section 3 and returns its path: /etc/porthole on Linux (0755; the files in it carry their own modes),
// /Library/Application Support/porthole on macOS (0750 root:admin) and %ProgramData%\porthole on Windows (a protected
// DACL: SYSTEM and Administrators only). It needs root or Administrator and is safe to call again; on Windows it
// resets a looser DACL of an existing directory.
func PrepareSystemDir() (string, error) {
	if !Elevated() {
		return "", ErrNotElevated
	}
	switch runtime.GOOS {
	case "linux":
		if err := os.MkdirAll(linuxSystemDir, 0o755); err != nil {
			return "", fmt.Errorf("create %s: %w", linuxSystemDir, err)
		}
		return linuxSystemDir, nil
	case "darwin":
		return darwinSystemDir, prepareDarwinDirs(context.Background(), execRunner{}, darwinSystemDir, darwinLogDir)
	case "windows":
		return prepareSystemDirWindows()
	default:
		return "", fmt.Errorf("system directory on %s: %w", runtime.GOOS, ErrUnsupported)
	}
}

// prepareDarwinDirs creates the configuration directory (0750 root:admin, so that the macOS administrators can read
// the files in it) and the log directory (0755).
func prepareDarwinDirs(ctx context.Context, r Runner, configDir, logDir string) error {
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", configDir, err)
	}
	if err := os.Chmod(configDir, 0o750); err != nil {
		return fmt.Errorf("chmod %s: %w", configDir, err)
	}
	if _, err := r.Run(ctx, "chown", "root:admin", configDir); err != nil {
		return fmt.Errorf("set the group of %s: %w", configDir, err)
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", logDir, err)
	}
	return nil
}
