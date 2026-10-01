// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import "golang.org/x/sys/windows"

// Elevated reports whether the process token is elevated (an Administrator in an elevated terminal, or LocalSystem).
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
