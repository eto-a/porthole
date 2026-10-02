// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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
		return darwinSystemDir, prepareDarwinDirs(context.Background(), execRunner{}, lstatMeta, darwinSystemDir, darwinLogDir)
	case "windows":
		return prepareSystemDirWindows()
	default:
		return "", fmt.Errorf("system directory on %s: %w", runtime.GOOS, ErrUnsupported)
	}
}

// prepareDarwinDirs creates the configuration directory (0750 root:admin, so that the macOS administrators can read
// the files in it) and the log directory (0755).
func prepareDarwinDirs(ctx context.Context, r Runner, lstat statFunc, configDir, logDir string) error {
	// A directory that is already there may have been made by someone else, with a symbolic link or a file of theirs
	// in it. The service runs as root, so such a directory is refused rather than adopted.
	for _, dir := range []string{configDir, logDir} {
		if err := verifyExistingDir(dir, lstat); err != nil {
			return err
		}
	}
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

// verifyExistingDir returns an error if dir exists and is not a directory made by root with only root-made content.
func verifyExistingDir(dir string, lstat statFunc) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := checkTreeUnix(dir, lstat, 0, trustedGroup); err != nil {
		return fmt.Errorf("%s exists but was not made by root (%w); inspect it, remove it and run this again", dir, err)
	}
	return nil
}
