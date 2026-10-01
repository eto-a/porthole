// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package localapi

import "net"

// peerCred: no peer credentials on this platform.
func peerCred(net.Conn) (Cred, bool) { return Cred{}, false }
