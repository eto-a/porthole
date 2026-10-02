// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package localapi

// CurrentSID returns "" on platforms without Windows SIDs.
func CurrentSID() string { return "" }
