// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"os"

	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

// ExitConfig is the exit status for a problem that restarting cannot fix (sysexits.h EX_CONFIG): a broken config or
// tunnels file, missing credentials, a token the server rejects. The systemd unit lists it in
// RestartPreventExitStatus so that a bad configuration does not turn into a restart loop.
const ExitConfig = exitcode.Config

// ExitError is an error that asks for a specific process exit status.
type ExitError = exitcode.Error

// ExitCode returns the process exit status for the error returned by the root command, see the table in
// docs/client.md: the Code of an *ExitError anywhere in the chain, else the status that classify gives the error
// (connection, authentication, rejected tunnel, daemon), else 1.
func ExitCode(err error) int { return exitcode.Status(err, classify) }

// classify maps the errors of the client to an exit status and the code of the --json error document.
func classify(err error) (int, string) {
	var perr *proto.Error
	if errors.As(err, &perr) {
		switch perr.Code {
		case proto.CodeUnauthorized, proto.CodeTokenRevoked, proto.CodeTokenExpired:
			return exitcode.Auth, perr.Code
		case proto.CodeNameTaken, proto.CodeForbidden, proto.CodeLimitExceeded, proto.CodePortUnavailable:
			return exitcode.Rejected, perr.Code
		}
	}
	var ice *client.InitialConnectError
	if errors.As(err, &ice) {
		return exitcode.Connect, ""
	}
	var noDaemon *noDaemonError
	var denied *deniedError
	switch {
	case errors.As(err, &noDaemon) || localapi.IsUnavailable(err):
		return exitcode.Daemon, ""
	case errors.As(err, &denied) || localapi.IsPermissionDenied(err):
		return exitcode.Daemon, "permission_denied"
	}
	var lerr *localapi.Error
	if errors.As(err, &lerr) {
		switch lerr.Code {
		case localapi.CodeNameTaken, localapi.CodeForbidden:
			return exitcode.Rejected, lerr.Code
		}
		return exitcode.General, lerr.Code
	}
	if perr != nil {
		return exitcode.General, perr.Code
	}
	return exitcode.General, ""
}

// Main runs the porthole command line and returns the process exit status. Failures are reported on stderr, or as an
// error document on stdout with --json.
func Main(ctx context.Context, version string) int {
	return exitcode.Run(ctx, NewRoot(version), "porthole", os.Args[1:], classify)
}

// configErr marks err as a configuration problem (exit status 78).
func configErr(err error) error { return &ExitError{Code: ExitConfig, Err: err} }

// usageErr marks err as a usage error (exit status 2) for a mistake the command finds in its own arguments.
func usageErr(err error) error { return exitcode.UsageError(err) }
