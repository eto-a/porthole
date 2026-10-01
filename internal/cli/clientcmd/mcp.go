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
	var readOnly bool
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve MCP tools on stdio to open and close tunnels through the local daemon",
		Long: "Serve MCP tools (open_tunnel, close_tunnel, list_tunnels, status) on stdin/stdout, e.g. for\n" +
			"`claude mcp add porthole-local -- porthole mcp`. The tools talk to the local porthole daemon over its unix\n" +
			"socket; access to the socket is the permission, no token is involved.",
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
			srv, err := mcpclient.New(mcpclient.Options{Dial: dial, ReadOnly: readOnly, Logger: a.logger(cmd), Version: a.version})
			if err != nil {
				return err
			}
			if err := srv.Run(cmd.Context(), &mcp.StdioTransport{}); err != nil && cmd.Context().Err() == nil {
				return fmt.Errorf("mcp: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "serve no tool that changes anything (only status and list_tunnels)")
	return cmd
}
