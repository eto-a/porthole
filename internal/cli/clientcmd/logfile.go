// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	// maxLogSize caps the service log: when the next write would pass it, the file becomes <name>.1 (replacing the
	// previous copy) and a new file starts, so the log never takes more than about twice this.
	maxLogSize = 10 << 20
	logDirName = "logs"
	logName    = "porthole.log"
)

// rotatingFile is an io.Writer onto a log file of bounded size with one rotated copy.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

// openRotatingFile opens (appending) the log file at path, creating its directory.
func openRotatingFile(path string, limit int64) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create the log directory: %w", err)
	}
	r := &rotatingFile{path: path, max: limit}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return fmt.Errorf("open the log file: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("open the log file: %w", err)
	}
	r.f, r.size = f, fi.Size()
	return nil
}

// Write implements io.Writer.
func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.size > 0 && r.size+int64(len(p)) > r.max {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("rotate the log: %w", err)
	}
	r.f = nil
	_ = os.Remove(r.path + ".1") // Windows cannot rename over an existing file
	if err := os.Rename(r.path, r.path+".1"); err != nil {
		return fmt.Errorf("rotate the log: %w", err)
	}
	return r.open()
}

// Close closes the file.
func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// serviceLogPath is the log file of the Windows service: %ProgramData%\porthole\logs\porthole.log (ADR 0006).
func serviceLogPath(getenv func(string) string) string {
	base := getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "porthole", logDirName, logName)
}
