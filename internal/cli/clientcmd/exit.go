// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import "errors"

// ExitConfig is the exit status for a problem that restarting cannot fix (sysexits.h EX_CONFIG): a broken config or
// tunnels file, missing credentials, a token the server rejects. The systemd unit lists it in
// RestartPreventExitStatus so that a bad configuration does not turn into a restart loop.
const ExitConfig = 78

// ExitError is an error that asks for a specific process exit status.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode returns the process exit status for the error returned by the root command: the Code of an *ExitError
// anywhere in the chain, and 1 for every other error.
func ExitCode(err error) int {
	var ee *ExitError
	if errors.As(err, &ee) && ee.Code > 0 {
		return ee.Code
	}
	return 1
}
