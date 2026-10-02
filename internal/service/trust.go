// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
)

// A system service runs with rights that its user lacks, so whatever the service starts or reads must not be
// replaceable by an unprivileged user: that would turn "may write there" into "runs as SYSTEM/root". This file holds
// the rules that do not depend on the platform (Unix permission bits; the Windows ACL rules are in trust_windows.go).
// The approach follows what package managers and systemd do for files they hand to a privileged service: owner root,
// no write for group or others, all the way up the directory chain.

// UnsafePathError says why a path may not be used by a privileged service.
type UnsafePathError struct {
	Path string // the file or directory that has the problem (an ancestor of the checked path, or the path itself)
	Why  string
}

func (e *UnsafePathError) Error() string { return e.Path + ": " + e.Why }

// fileMeta is the part of the file status that the Unix rules look at.
type fileMeta struct {
	UID, GID uint32
	Mode     fs.FileMode
}

// statFunc returns the status of a file. It does not follow a final symbolic link when it is a Lstat.
type statFunc func(path string) (fileMeta, error)

// checkEntryUnix applies the rules to one file or directory: owned by wantUID, not writable by others, and writable
// by a group only if groupOK accepts the group.
func checkEntryUnix(p string, m fileMeta, wantUID uint32, groupOK func(gid uint32) bool) error {
	switch {
	case m.UID != wantUID:
		return &UnsafePathError{p, fmt.Sprintf("is owned by uid %d, not by uid %d", m.UID, wantUID)}
	case m.Mode.Perm()&0o002 != 0:
		return &UnsafePathError{p, "is writable by every user"}
	case m.Mode.Perm()&0o020 != 0 && (groupOK == nil || !groupOK(m.GID)):
		return &UnsafePathError{p, fmt.Sprintf("is writable by group %d", m.GID)}
	}
	return nil
}

// checkChainUnix checks target and every directory above it (as slash-separated absolute path). The parts that do
// not exist are skipped: a file that is about to be created is protected by its directory.
func checkChainUnix(target string, stat statFunc, wantUID uint32, groupOK func(gid uint32) bool) error {
	if !path.IsAbs(target) {
		return fmt.Errorf("%q is not an absolute path", target)
	}
	for p := path.Clean(target); ; p = path.Dir(p) {
		m, err := stat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return &UnsafePathError{p, "cannot be examined: " + err.Error()}
		default:
			if err := checkEntryUnix(p, m, wantUID, groupOK); err != nil {
				return err
			}
		}
		if p == "/" {
			return nil
		}
	}
}

// checkTreeUnix checks that nothing inside the directory root can have been put there by someone else: root and
// every entry below it is owned by wantUID, no entry is a symbolic link (or any other kind of indirection), and none
// is writable by others or, unless groupOK accepts the group, by a group. lstat must not follow links.
func checkTreeUnix(root string, lstat statFunc, wantUID uint32, groupOK func(gid uint32) bool) error {
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return &UnsafePathError{p, "cannot be examined: " + err.Error()}
		}
		m, err := lstat(p)
		if err != nil {
			return &UnsafePathError{p, "cannot be examined: " + err.Error()}
		}
		if m.Mode&(fs.ModeSymlink|fs.ModeIrregular|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket) != 0 {
			return &UnsafePathError{p, "is a symbolic link or a special file"}
		}
		return checkEntryUnix(p, m, wantUID, groupOK)
	})
}

// lstatMeta is the [statFunc] of the real file system that does not follow links; the metadata comes from metaOf.
func lstatMeta(p string) (fileMeta, error) { return metaFrom(os.Lstat(p)) }

func metaFrom(fi fs.FileInfo, err error) (fileMeta, error) {
	if err != nil {
		return fileMeta{}, err
	}
	m, ok := metaOf(fi)
	if !ok {
		return fileMeta{}, errors.New("the file system gives no owner information")
	}
	return m, nil
}

// trustedGroup reports whether group writes are acceptable: the group of root, and on macOS the admin group (80),
// whose members can become root anyway.
func trustedGroup(gid uint32) bool { return gid == 0 || (runtime.GOOS == "darwin" && gid == 80) }
