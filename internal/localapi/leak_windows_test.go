// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localapi

import "go.uber.org/goleak"

// leakOptions: go-winio starts one process-wide I/O completion goroutine on first use and never stops it. The tests
// with a raw go-winio listener leave its Close behind when it hangs (closeListener in pipe_windows_test.go), together
// with the listener goroutine it waits for.
func leakOptions() []goleak.Option {
	return []goleak.Option{
		goleak.IgnoreAnyFunction("github.com/Microsoft/go-winio.ioCompletionProcessor"),
		goleak.IgnoreAnyFunction("github.com/Microsoft/go-winio.(*win32PipeListener).listenerRoutine"),
		goleak.IgnoreAnyFunction("github.com/Microsoft/go-winio.(*win32PipeListener).Close"),
	}
}
