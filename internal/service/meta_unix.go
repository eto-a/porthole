// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package service

import (
	"io/fs"
	"os"
	"syscall"
)

// statMeta is like lstatMeta but follows a final link.
func statMeta(p string) (fileMeta, error) { return metaFrom(os.Stat(p)) }

// metaOf extracts the owner of a file from the result of Stat or Lstat.
func metaOf(fi fs.FileInfo) (fileMeta, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileMeta{}, false
	}
	return fileMeta{UID: st.Uid, GID: st.Gid, Mode: fi.Mode()}, true
}

// VerifyProtectedDir returns an error unless dir and everything in it is owned by root, is not a link or a special
// file, and is not writable by others (or by a group other than root's or, on macOS, admin).
func VerifyProtectedDir(dir string) error {
	return checkTreeUnix(dir, lstatMeta, 0, trustedGroup)
}

// CheckTrustedPath returns an *[UnsafePathError] unless path and all of its parent directories are owned by root and
// not writable by others (or by a group other than root's or, on macOS, admin). A path that does not exist yet is
// judged by its closest existing parent.
func CheckTrustedPath(path string) error {
	return checkChainUnix(path, statMeta, 0, trustedGroup)
}
