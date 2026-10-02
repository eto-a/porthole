// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package clientcmd

// handToServiceAccount does nothing: the macOS service runs as root, and the directory (0750 root) already limits
// who can read the files.
func handToServiceAccount(string, string) (bool, error) { return false, nil }
