// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// selfExecutable returns the absolute path of the running binary with symbolic links resolved (a service must not
// point at a link that a package manager may move).
func selfExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return "", fmt.Errorf("make %s absolute: %w", exe, err)
	}
	return abs, nil
}
