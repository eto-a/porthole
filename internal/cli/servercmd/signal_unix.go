// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package servercmd

import (
	"os"
	"syscall"
)

// reloadSignals lists the signals that make portholed re-read its TLS certificate: SIGHUP, the convention of
// Prometheus and Traefik, and what `systemctl reload` sends through ExecReload=/bin/kill -HUP $MAINPID.
func reloadSignals() []os.Signal { return []os.Signal{syscall.SIGHUP} }
