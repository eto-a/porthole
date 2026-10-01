// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/client"
)

// The "event" values of the JSON Lines a running command writes to stdout with --json.
const (
	eventConnected    = "connected"
	eventTunnelReady  = "tunnel_ready"
	eventTunnelClosed = "tunnel_closed"
	eventDisconnected = "disconnected"
)

// jsonEvent is one JSON Lines record of `porthole http|tcp|ssh|start --json`. "event" is always set; the other
// members depend on it:
//
//	connected     client
//	tunnel_ready  name, kind, local_addr, public_url (http, tcp), ssh_jump (ssh gateway), private
//	tunnel_closed name, reason
//	disconnected  error, retry_in_ms, attempt and max_attempts (while no session has been established yet)
type jsonEvent struct {
	Event       string `json:"event"`
	Client      string `json:"client,omitempty"`
	Name        string `json:"name,omitempty"`
	Kind        string `json:"kind,omitempty"`
	LocalAddr   string `json:"local_addr,omitempty"`
	PublicURL   string `json:"public_url,omitempty"`
	SSHJump     string `json:"ssh_jump,omitempty"`
	Private     *bool  `json:"private,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Error       string `json:"error,omitempty"`
	RetryInMS   *int64 `json:"retry_in_ms,omitempty"`
	Attempt     int    `json:"attempt,omitempty"`
	MaxAttempts int    `json:"max_attempts,omitempty"`
}

// toJSONEvent converts a client event; ok is false for events that have no JSON form.
func toJSONEvent(e client.Event) (jsonEvent, bool) {
	switch e := e.(type) {
	case client.Connected:
		return jsonEvent{Event: eventConnected, Client: e.ClientName}, true
	case client.TunnelReady:
		private := e.Spec.Private
		return jsonEvent{
			Event: eventTunnelReady, Name: e.Name, Kind: e.Spec.Kind, LocalAddr: e.Spec.LocalAddr,
			PublicURL: e.PublicURL, SSHJump: e.SSHJump, Private: &private,
		}, true
	case client.TunnelClosed:
		return jsonEvent{Event: eventTunnelClosed, Name: e.Name, Reason: e.Reason}, true
	case client.Disconnected:
		retry := e.RetryIn.Milliseconds()
		ev := jsonEvent{Event: eventDisconnected, RetryInMS: &retry, Attempt: e.Attempt, MaxAttempts: e.MaxAttempts}
		if e.Err != nil {
			ev.Error = e.Err.Error()
		}
		return ev, true
	default:
		return jsonEvent{}, false
	}
}

// eventSink returns the function that reports client events of cmd: JSON Lines on stdout with --json, otherwise text
// for the terminal (printEvent). labelled puts the tunnel name before the address, for commands with several tunnels.
func eventSink(cmd *cobra.Command, hint *sshHint, labelled bool) func(client.Event) {
	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if jsonout.Enabled(cmd) {
		lines := jsonout.NewLines(out)
		return func(e client.Event) {
			if ev, ok := toJSONEvent(e); ok {
				_ = lines.Emit(ev)
			}
		}
	}
	return func(e client.Event) {
		if r, ok := e.(client.TunnelReady); ok && labelled {
			printLabelledReady(out, r)
			return
		}
		printEvent(out, errOut, e, hint)
	}
}

// printLabelledReady renders a ready tunnel as "<name>: <address> -> <local>".
func printLabelledReady(out io.Writer, r client.TunnelReady) {
	if r.SSHJump != "" {
		fmt.Fprintf(out, "%s: ssh via %s -> %s\n", r.Name, r.SSHJump, r.Spec.LocalAddr)
		return
	}
	fmt.Fprintf(out, "%s: %s -> %s\n", r.Name, r.PublicURL, r.Spec.LocalAddr)
}
