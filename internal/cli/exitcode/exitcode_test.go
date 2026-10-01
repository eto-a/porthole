// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package exitcode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/jsonout"
)

func testRoot() *cobra.Command {
	root := &cobra.Command{Use: "tool"}
	jsonout.AddFlag(root)
	root.AddCommand(
		&cobra.Command{Use: "ok", RunE: func(*cobra.Command, []string) error { return nil }},
		&cobra.Command{Use: "boom", RunE: func(*cobra.Command, []string) error { return errors.New("boom") }},
		&cobra.Command{Use: "cfg", RunE: func(*cobra.Command, []string) error { return ConfigError(errors.New("bad config")) }},
		&cobra.Command{Use: "plain", Run: func(*cobra.Command, []string) {}},
		&cobra.Command{Use: "one", Args: cobra.ExactArgs(1), RunE: func(*cobra.Command, []string) error { return nil }},
		&cobra.Command{Use: "quiet", RunE: func(*cobra.Command, []string) error {
			return &Error{Code: Rejected, Err: errors.New("partial"), Quiet: true}
		}},
	)
	return root
}

func TestRun(t *testing.T) {
	classify := func(err error) (int, string) {
		if err.Error() == "boom" {
			return Connect, ""
		}
		return 0, ""
	}
	tests := []struct {
		args     []string
		want     int
		wantCode string // the "code" of the --json error document; "" for none
	}{
		{[]string{"ok"}, OK, ""},
		{[]string{"plain"}, OK, ""},
		{[]string{"boom"}, Connect, "connect_failed"},
		{[]string{"cfg"}, Config, "config"},
		{[]string{"one"}, Usage, "usage"},
		{[]string{"one", "a", "b"}, Usage, "usage"},
		{[]string{"nope"}, Usage, "usage"},
		{[]string{"ok", "--bogus"}, Usage, "usage"},
		{[]string{"quiet"}, Rejected, ""},
	}
	for _, tc := range tests {
		for _, asJSON := range []bool{false, true} {
			args := tc.args
			if asJSON {
				args = append([]string{"--json"}, args...)
			}
			root := testRoot()
			var out, errOut bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&errOut)
			if got := Run(context.Background(), root, "tool", args, classify); got != tc.want {
				t.Errorf("%v: exit %d, want %d", args, got, tc.want)
			}
			switch {
			case asJSON && tc.wantCode != "":
				var doc jsonout.ErrorDoc
				if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Error.Code != tc.wantCode || doc.Error.Message == "" {
					t.Errorf("%v: stdout %q (%v), want an error document with code %q", args, out.String(), err, tc.wantCode)
				}
			case asJSON:
				if out.Len() != 0 {
					t.Errorf("%v: unexpected stdout %q", args, out.String())
				}
			case tc.want != OK && errOut.Len() == 0:
				t.Errorf("%v: no message on stderr", args)
			}
		}
	}
}

func TestStatus(t *testing.T) {
	if Status(nil, nil) != OK || Status(errors.New("x"), nil) != General {
		t.Error("nil is 0, an unknown error is 1")
	}
	if got := Status(&Error{Code: 0, Err: errors.New("x")}, nil); got != General {
		t.Errorf("a zero code must not mean success: %d", got)
	}
	if got := Status(errors.Join(errors.New("a"), ConfigError(errors.New("b"))), nil); got != Config {
		t.Errorf("a wrapped Error: %d", got)
	}
}

func TestInArgs(t *testing.T) {
	for args, want := range map[string]bool{"--json": true, "--json=true": true, "--json=false": false, "-- --json": false, "": false} {
		if got := jsonout.InArgs(strings.Fields(args)); got != want {
			t.Errorf("InArgs(%q) = %v, want %v", args, got, want)
		}
	}
}
