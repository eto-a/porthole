// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package servercmd

import "os"

// reloadSignals is empty where there is no SIGHUP (Windows); the certificate is still picked up by the
// periodic modification-time check.
func reloadSignals() []os.Signal { return nil }
