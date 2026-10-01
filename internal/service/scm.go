// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"fmt"
	"strings"
	"time"
)

// Recovery ladder of the Windows service (ADR 0006 section 1): restart after 1 s, 5 s and 30 s; the failure count
// is reset after a day without failures.
var scmRecoveryDelays = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}

const scmResetPeriod = 24 * time.Hour

// scmConfig is the definition of the Windows service as the install code applies it. It is plain data without any
// Windows type, so that the golden test renders it on every OS; the Windows code maps it to mgr.Config.
type scmConfig struct {
	Name        string
	DisplayName string
	Description string
	// CommandLine is the BinaryPathName: the quoted path of the binary and its arguments.
	CommandLine string
	// Account is empty for LocalSystem.
	Account string
	// RecoveryOnNonCrash makes the recovery actions apply when the service stops with a non-zero exit code too, not
	// only when the process dies (the equivalent of Restart=on-failure).
	RecoveryOnNonCrash bool
}

func buildSCMConfig(spec Spec) scmConfig {
	return scmConfig{
		Name:               spec.Name,
		DisplayName:        spec.DisplayName,
		Description:        spec.Description,
		CommandLine:        composeWindowsCommandLine(append([]string{spec.Exe}, spec.Args...)),
		RecoveryOnNonCrash: true,
	}
}

// String renders the definition as text (the golden file).
func (c scmConfig) String() string {
	var b strings.Builder
	account := c.Account
	if account == "" {
		account = "LocalSystem"
	}
	fmt.Fprintf(&b, "name: %s\n", c.Name)
	fmt.Fprintf(&b, "display name: %s\n", c.DisplayName)
	fmt.Fprintf(&b, "description: %s\n", c.Description)
	fmt.Fprintf(&b, "command line: %s\n", c.CommandLine)
	fmt.Fprintf(&b, "account: %s\n", account)
	b.WriteString("start type: automatic, delayed\n")
	b.WriteString("error control: normal\n")
	for i, d := range scmRecoveryDelays {
		fmt.Fprintf(&b, "recovery %d: restart after %s\n", i+1, d)
	}
	fmt.Fprintf(&b, "recovery reset period: %s\n", scmResetPeriod)
	fmt.Fprintf(&b, "recovery on non-crash failures: %t\n", c.RecoveryOnNonCrash)
	fmt.Fprintf(&b, "event log source: %s (error, warning, information)\n", c.Name)
	return b.String()
}

// composeWindowsCommandLine joins arguments into one command line that CommandLineToArgvW splits back into the same
// arguments. It follows the documented quoting rules and is checked against windows.ComposeCommandLine in the
// Windows tests.
func composeWindowsCommandLine(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = escapeWindowsArg(a)
	}
	return strings.Join(q, " ")
}

func escapeWindowsArg(s string) string {
	if s == "" {
		return `""`
	}
	wrap := strings.ContainsAny(s, " \t") // like windows.EscapeArg: only white space forces quotes
	if !wrap && !strings.Contains(s, `"`) {
		return s
	}
	var b strings.Builder
	if wrap {
		b.WriteByte('"')
	}
	backslashes := 0
	for i := range len(s) {
		c := s[i]
		switch c {
		case '\\':
			backslashes++
			b.WriteByte(c)
		case '"':
			// Backslashes before a quote are doubled, and the quote itself is escaped.
			b.WriteString(strings.Repeat(`\`, backslashes+1))
			b.WriteByte(c)
			backslashes = 0
		default:
			backslashes = 0
			b.WriteByte(c)
		}
	}
	if wrap {
		// Backslashes before the closing quote are doubled so that they do not escape it.
		b.WriteString(strings.Repeat(`\`, backslashes))
		b.WriteByte('"')
	}
	return b.String()
}
