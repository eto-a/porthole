// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	mcpclient "github.com/eto-a/porthole/internal/mcp/client"
)

// newMCPCmd is `porthole mcp`: the agent-facing MCP server on stdio (ADR 0005, surface B). Every tool call looks
// for the daemon anew (--socket, $PORTHOLE_SOCKET, then the default sockets), so the agent may start first.
func (a *app) newMCPCmd() *cobra.Command {
	var readOnly, allowRemote bool
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve MCP tools on stdio to open and close tunnels through the local daemon",
		Long: "Serve MCP tools (open_tunnel, close_tunnel, list_tunnels, status) on stdin/stdout, e.g. for\n" +
			"`claude mcp add porthole-local -- porthole mcp`. The tools talk to the local porthole daemon over its unix\n" +
			"socket; access to the socket is the permission, no token is involved.\n" +
			"open_tunnel only exposes services on this machine (127.0.0.1, ::1, localhost) unless --allow-remote-targets is\n" +
			"given; use --read-only when the agent reads untrusted content.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dial := func(ctx context.Context) (mcpclient.Daemon, func(), error) {
				cl, _, err := a.requireDaemon(ctx)
				if err != nil {
					return nil, nil, err
				}
				return cl, cl.Close, nil
			}
			// stdout carries the protocol: logs go to stderr.
			diagnose := func(ctx context.Context) mcpclient.DiagnoseResult { return a.diagnose(ctx, cmd) }
			srv, err := mcpclient.New(mcpclient.Options{
				Dial: dial, ReadOnly: readOnly, AllowRemoteTargets: allowRemote, Logger: a.logger(cmd), Version: a.version,
				Diagnose: diagnose,
			})
			if err != nil {
				return err
			}
			if err := srv.Run(cmd.Context(), &mcp.StdioTransport{}); err != nil && cmd.Context().Err() == nil {
				return fmt.Errorf("mcp: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "serve no tool that changes anything (only status, list_tunnels and diagnose)")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote-targets", false,
		"let open_tunnel publish hosts other than this machine (LAN addresses, names); by default only 127.0.0.1, ::1 and localhost")
	return cmd
}

// diagnose runs the checks of `porthole doctor` for the MCP tool of the same name.
func (a *app) diagnose(ctx context.Context, cmd *cobra.Command) mcpclient.DiagnoseResult {
	var r doctorReport
	if p, err := a.doctorConfigPath(false); err != nil {
		r = doctorReport{Checks: []doctorCheck{{Name: "config", Status: doctorFail, Message: err.Error()}}}
	} else {
		r = a.runDoctor(ctx, cmd, p, false)
	}
	out := mcpclient.DiagnoseResult{OK: r.OK, Checks: make([]mcpclient.DiagnoseCheck, 0, len(r.Checks))}
	for _, c := range r.Checks {
		out.Checks = append(out.Checks, mcpclient.DiagnoseCheck(c))
	}
	return out
}
