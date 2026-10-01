// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package clientcmd

// handToServiceAccount does nothing: the macOS service runs as root and the Windows one as LocalSystem, and the
// directory (0750 root:admin, a protected DACL) already limits who can read the files.
func handToServiceAccount(string, string) (bool, error) { return false, nil }
