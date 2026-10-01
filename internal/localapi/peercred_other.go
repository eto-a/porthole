// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package localapi

import "net"

// peerCred: no peer credentials on this platform (Windows has no portable way for AF_UNIX in Go's net package).
func peerCred(net.Conn) (Cred, bool) { return Cred{}, false }
