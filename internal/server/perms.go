// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
)

// tightenDir makes sure an existing directory holding secrets (the database, the SSH host key, certificate keys)
// is not accessible to group or others, as OpenSSH insists for host keys: a directory created earlier with a
// looser mode or by another tool keeps it, MkdirAll(path, 0o700) does not change it. A missing directory is not an
// error. When the mode cannot be changed (not the owner) the problem is logged and the server starts anyway. Unix
// permission bits mean nothing on Windows, so nothing is checked there.
func tightenDir(path string, log *slog.Logger) {
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			log.Warn("directory with secrets is accessible to other users and its mode cannot be changed",
				"path", path, "mode", fmt.Sprintf("%04o", mode), "err", err)
			return
		}
		log.Warn("directory with secrets was accessible to other users; mode set to 0700",
			"path", path, "was", fmt.Sprintf("%04o", mode))
	}
}

// ensurePrivateDir creates path (mode 0700) if needed and tightens it like tightenDir.
func ensurePrivateDir(path string, log *slog.Logger) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	tightenDir(path, log)
	return nil
}
