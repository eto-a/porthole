// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package jsonout implements the --json mode shared by the porthole and portholed command lines. In this mode stdout
// carries only JSON: one object (or array) for a command that ends by itself, one compact object per line (JSON Lines)
// for a command that keeps running and reports events. Everything meant for people goes to stderr or is left out.
package jsonout

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/spf13/cobra"
)

// Flag is the name of the persistent flag of the root commands.
const Flag = "json"

// AddFlag registers the persistent --json flag on root.
func AddFlag(root *cobra.Command) {
	root.PersistentFlags().Bool(Flag, false, "machine-readable output: JSON on stdout (JSON Lines for commands that keep running)")
}

// Enabled reports whether --json was given to cmd or to one of its parents.
func Enabled(cmd *cobra.Command) bool {
	on, err := cmd.Flags().GetBool(Flag)
	return err == nil && on
}

// InArgs reports whether args ask for --json. It is for command lines that failed to parse, where the flag set holds
// no value yet.
func InArgs(args []string) bool {
	for _, a := range args {
		switch a {
		case "--":
			return false
		case "--" + Flag, "--" + Flag + "=true":
			return true
		}
	}
	return false
}

// Write writes v as one indented JSON document.
func Write(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Lines writes JSON Lines: one compact object per call, safe for concurrent use.
type Lines struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewLines returns a Lines that writes to w.
func NewLines(w io.Writer) *Lines { return &Lines{enc: json.NewEncoder(w)} }

// Emit writes v as one line.
func (l *Lines) Emit(v any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(v)
}

// ErrorBody is the content of the "error" member of a failure document.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrorDoc is what a failed command writes to stdout in --json mode: {"error":{"code":"...","message":"..."}}.
type ErrorDoc struct {
	Error ErrorBody `json:"error"`
}

// WriteError writes the failure document as one line.
func WriteError(w io.Writer, code, message string) error {
	return json.NewEncoder(w).Encode(ErrorDoc{Error: ErrorBody{Code: code, Message: message}})
}
