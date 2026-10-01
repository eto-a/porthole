// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/config"
	mcpserver "github.com/eto-a/porthole/internal/mcp/server"
)

// NewMCP returns the `mcp` command: the operator MCP server on stdin/stdout (ADR 0005, surface A). It reaches the
// running server through the admin unix socket, so whoever may open the socket may use every tool; run it over ssh
// (`claude mcp add porthole -- ssh host portholed mcp`) or locally on the server.
func NewMCP(load func() (*config.Config, error), version string) *cobra.Command {
	var (
		socket   string
		toolsets string
		readOnly bool
	)
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve the operator MCP tools on stdio, over the admin socket",
		Long: "Serve the porthole operator tools (server status, clients, tunnels, tokens, audit log) to an MCP client on " +
			"stdin/stdout. Requires the admin socket of the running portholed. Traffic tools are served by the HTTP " +
			"endpoint /_porthole/mcp only.\n\nToolsets: " + joinToolsets() + ".",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sets, err := mcpserver.ParseToolsets(toolsets)
			if err != nil {
				return err
			}
			path, err := adminSocketPath(load, socket)
			if err != nil {
				return err
			}
			// stdout carries the protocol: logs go to stderr.
			log := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn}))
			srv, err := mcpserver.New(mcpserver.SocketOps{Client: adminapi.NewSocketClient(path)}, mcpserver.Options{
				Toolsets: sets, ReadOnly: readOnly, Logger: log, Version: version,
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
	cmd.Flags().StringVar(&socket, "socket", "", "admin socket path (default: from the configuration)")
	cmd.Flags().StringVar(&toolsets, "toolsets", "", "comma-separated toolsets to enable (default: all): "+joinToolsets())
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "serve no tool that changes anything")
	return cmd
}

func joinToolsets() string { return strings.Join(mcpserver.AllToolsets, ", ") }
