// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localapi

import "go.uber.org/goleak"

// leakOptions: go-winio starts one process-wide I/O completion goroutine on first use and never stops it.
func leakOptions() []goleak.Option {
	return []goleak.Option{goleak.IgnoreAnyFunction("github.com/Microsoft/go-winio.ioCompletionProcessor")}
}
