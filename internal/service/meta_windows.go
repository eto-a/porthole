// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package service

import "io/fs"

// metaOf: Windows has no uid and gid; the Unix rules are not used here.
func metaOf(fs.FileInfo) (fileMeta, bool) { return fileMeta{}, false }
