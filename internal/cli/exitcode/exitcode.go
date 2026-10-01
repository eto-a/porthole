// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package exitcode defines the process exit statuses of porthole and portholed, and runs a cobra command tree so that
// every failure ends in one of them (and, with --json, in an error document on stdout).
package exitcode

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/jsonout"
)

// The exit statuses. docs/client.md and docs/server.md list them for users.
const (
	OK       = 0  // success
	General  = 1  // any other failure
	Usage    = 2  // wrong flags or arguments
	Connect  = 3  // the server could not be reached
	Auth     = 4  // the server refused the token (unauthorized, token_revoked, token_expired)
	Rejected = 5  // the server refused a tunnel (name_taken, forbidden, limit_exceeded, port_unavailable)
	Daemon   = 6  // the local daemon is not running, or this user may not use its socket
	Config   = 78 // a configuration problem that restarting cannot fix (sysexits.h EX_CONFIG)
)

// Name is the "code" of the error document for an exit status that has no more specific code.
func Name(code int) string {
	switch code {
	case Usage:
		return "usage"
	case Connect:
		return "connect_failed"
	case Auth:
		return "auth_failed"
	case Rejected:
		return "tunnel_rejected"
	case Daemon:
		return "daemon_unavailable"
	case Config:
		return "config"
	default:
		return "error"
	}
}

// Error is an error that asks for a specific exit status.
type Error struct {
	Code int
	Err  error
	// Quiet means the command already wrote its own result document in --json mode, so no error document follows.
	Quiet bool
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// UsageError marks err as a usage error (exit status Usage).
func UsageError(err error) error { return &Error{Code: Usage, Err: err} }

// ConfigError marks err as a configuration problem (exit status Config).
func ConfigError(err error) error { return &Error{Code: Config, Err: err} }

// Classifier maps an error that is not an *Error to an exit status and, optionally, a specific error code for the
// error document ("" selects Name(status)). A status of 0 or less means "not recognised".
type Classifier func(err error) (status int, code string)

// Status returns the exit status for err: 0 for nil, the Code of an *Error anywhere in the chain, else what classify
// (may be nil) says, else General.
func Status(err error, classify Classifier) int {
	st, _ := resolve(err, classify)
	return st
}

func resolve(err error, classify Classifier) (status int, code string) {
	if err == nil {
		return OK, ""
	}
	var ee *Error
	if errors.As(err, &ee) && ee.Code > 0 {
		return ee.Code, Name(ee.Code)
	}
	if classify != nil {
		if st, c := classify(err); st > 0 {
			if c == "" {
				c = Name(st)
			}
			return st, c
		}
	}
	return General, Name(General)
}

// Run executes root with args (without the program name) and returns the exit status. A failure is written as "prog: message" to stderr, or, with --json,
// as an error document to stdout. Any error that happens before a command started running (unknown command, bad
// flag, wrong number of arguments, a required flag missing) is a usage error. root must have jsonout.AddFlag applied.
func Run(ctx context.Context, root *cobra.Command, prog string, args []string, classify Classifier) int {
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.SetArgs(args)
	started := false
	markStarted(root, &started)

	err := root.ExecuteContext(ctx)
	if err == nil {
		return OK
	}
	var ee *Error
	if !started && !errors.As(err, &ee) {
		err = UsageError(err)
	}
	status, code := resolve(err, classify)
	// A command line that failed to parse may not have got as far as the --json flag: look at the arguments too.
	asJSON := jsonout.Enabled(root) || (!started && jsonout.InArgs(args))
	report(root.OutOrStdout(), root.ErrOrStderr(), prog, asJSON, err, code)
	return status
}

func report(out, errOut io.Writer, prog string, asJSON bool, err error, code string) {
	if !asJSON {
		fmt.Fprintf(errOut, "%s: %v\n", prog, err)
		return
	}
	var ee *Error
	if errors.As(err, &ee) && ee.Quiet {
		return
	}
	_ = jsonout.WriteError(out, code, err.Error())
}

// markStarted wraps the run function of every command in the tree so that started becomes true once a command has
// begun to run: from then on an error is the command's own, not a usage error.
func markStarted(c *cobra.Command, started *bool) {
	switch {
	case c.RunE != nil:
		run := c.RunE
		c.RunE = func(cmd *cobra.Command, args []string) error {
			*started = true
			return run(cmd, args)
		}
	case c.Run != nil:
		run := c.Run
		c.Run = nil
		c.RunE = func(cmd *cobra.Command, args []string) error {
			*started = true
			run(cmd, args)
			return nil
		}
	}
	for _, sub := range c.Commands() {
		markStarted(sub, started)
	}
}
