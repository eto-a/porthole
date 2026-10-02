// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Where `porthole service install` puts a copy of itself when the running binary lies where users who are not
// administrators could replace it (a Homebrew prefix, Downloads): a fixed place that only administrators can write,
// like tailscaled's install-system-daemon, which copies itself to a fixed path. On Windows it is %ProgramData%\porthole\bin.
const (
	linuxInstallDir  = "/usr/local/lib/porthole"
	darwinInstallDir = darwinSystemDir + "/bin"
)

// InstallSelf copies the executable src to the protected install location and returns the path of the copy. The
// directory is created if needed and verified before anything is written into it; the copy is written to a temporary
// file next to the target, flushed to disk and renamed over it, so the target is never half written. It needs root or
// Administrator and is safe to call again (an upgrade replaces the copy).
func InstallSelf(src string) (string, error) {
	if !Elevated() {
		return "", ErrNotElevated
	}
	dir, err := prepareInstallDir()
	if err != nil {
		return "", err
	}
	if err := CheckTrustedPath(dir); err != nil {
		return "", fmt.Errorf("the install directory %s cannot be trusted: %w", dir, err)
	}
	name := "porthole"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dst := filepath.Join(dir, name)
	if err := copyFileAtomic(src, dst, secureCopy); err != nil {
		return "", err
	}
	return dst, nil
}

func prepareInstallDir() (string, error) {
	switch runtime.GOOS {
	case "linux":
		if err := os.MkdirAll(linuxInstallDir, 0o755); err != nil {
			return "", fmt.Errorf("create %s: %w", linuxInstallDir, err)
		}
		return linuxInstallDir, nil
	case "darwin":
		// PrepareSystemDir verifies an existing tree (bin included) before anything is created.
		if _, err := PrepareSystemDir(); err != nil {
			return "", err
		}
		if err := os.MkdirAll(darwinInstallDir, 0o755); err != nil {
			return "", fmt.Errorf("create %s: %w", darwinInstallDir, err)
		}
		return darwinInstallDir, nil
	case "windows":
		return prepareInstallDirWindows()
	default:
		return "", fmt.Errorf("install directory on %s: %w", runtime.GOOS, ErrUnsupported)
	}
}

// copyFileAtomic copies src to dst through a temporary file in the directory of dst (mode 0755), fsync and rename.
// secure, if set, fixes the ownership of the temporary file before it takes the place of dst.
func copyFileAtomic(src, dst string, secure func(string) error) (err error) {
	in, err := openSource(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	if sfi, err := in.Stat(); err == nil {
		if dfi, err := os.Stat(dst); err == nil && os.SameFile(sfi, dfi) {
			return fmt.Errorf("%s is already the install location of porthole", src)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".porthole-*.tmp")
	if err != nil {
		return fmt.Errorf("create a temporary file in %s: %w", filepath.Dir(dst), err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, in); err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	if err = tmp.Chmod(0o755); err != nil {
		return fmt.Errorf("make %s executable: %w", tmp.Name(), err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("flush %s: %w", tmp.Name(), err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}
	if secure != nil {
		err = secure(tmp.Name())
		if err != nil {
			return err
		}
	}
	if err = os.Rename(tmp.Name(), dst); err != nil {
		if runtime.GOOS == "windows" && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("replace %s (is the porthole service running from it? run `porthole service stop` first): %w", dst, err)
		}
		return fmt.Errorf("replace %s: %w", dst, err)
	}
	return nil
}

// openSource opens the binary to copy. On Linux the running image itself (/proc/self/exe) is read when src is the
// running executable: a user who may write src's directory could otherwise swap the file between the check that
// sent us here and the copy. Elsewhere src is opened by path; whoever can swap it could have swapped it before the
// administrator ran it as well.
func openSource(src string) (*os.File, error) {
	if runtime.GOOS == "linux" {
		if self, err := os.Open("/proc/self/exe"); err == nil {
			sfi, err1 := self.Stat()
			pfi, err2 := os.Stat(src)
			if err1 == nil && err2 == nil && os.SameFile(sfi, pfi) {
				return self, nil
			}
			_ = self.Close()
		}
	}
	return os.Open(src)
}
