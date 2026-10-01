// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/config"
)

const adminCallTimeout = 15 * time.Second

// NewAdmin returns the `admin` command group: clients of the running server's admin API over its unix socket.
// Access to the socket is the permission, so the commands need no token and must run as a user that may open it.
func NewAdmin(load func() (*config.Config, error)) *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Query the running server through its admin socket",
	}
	cmd.PersistentFlags().StringVar(&socket, "socket", "", "admin socket path (default: from the configuration)")

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show the server version, uptime and counters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := adminSocketPath(load, socket)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), adminCallTimeout)
			defer cancel()
			st, err := adminapi.NewSocketClient(path).Status(ctx)
			if err != nil {
				return fmt.Errorf("%w (socket %s; is portholed running and the socket readable by you?)", err, path)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "version:  %s\n", st.Version)
			fmt.Fprintf(out, "started:  %s\n", st.StartedAt.UTC().Format(time.RFC3339))
			fmt.Fprintf(out, "uptime:   %s\n", (time.Duration(st.UptimeSeconds) * time.Second).String())
			fmt.Fprintf(out, "clients:  %d\n", st.Clients)
			fmt.Fprintf(out, "tunnels:  %d\n", st.Tunnels)
			return nil
		},
	})
	cmd.AddCommand(newAdminOpen(load, &socket))
	cmd.AddCommand(newAdminReleaseLabel(load, &socket))
	return cmd
}

func adminSocketPath(load func() (*config.Config, error), override string) (string, error) {
	if override != "" {
		return override, nil
	}
	cfg, err := load()
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	path := cfg.AdminSocketPath()
	if path == "" {
		return "", errors.New("the admin socket is turned off (admin_socket: \"-\")")
	}
	return path, nil
}

// newAdminReleaseLabel returns `admin release-label`: free a hostname label that is claimed for good by the first
// client and tunnel that registered it.
func newAdminReleaseLabel(load func() (*config.Config, error), socket *string) *cobra.Command {
	return &cobra.Command{
		Use:   "release-label <label>",
		Short: "Free a hostname label that is permanently claimed by a client's tunnel",
		Long: "A tunnel's hostname label (\"<tunnel>-<client>\"; for ssh also the bare client name of the tunnel \"ssh\")\n" +
			"belongs to the first client and tunnel that registered it, until that client's token is revoked. Two\n" +
			"different pairs can compose the same label (client \"home\" with tunnel \"web-a\", client \"a-home\" with\n" +
			"tunnel \"web\"); the later one is refused with name_taken. This command takes the label away from its\n" +
			"owner so that anybody can register it.",
		Example: "  portholed admin release-label web-a-home",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := adminSocketPath(load, *socket)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), adminCallTimeout)
			defer cancel()
			if err := adminapi.NewSocketClient(path).ReleaseLabel(ctx, args[0]); err != nil {
				var ae *adminapi.Error
				if errors.As(err, &ae) && ae.HTTPStatus == 404 {
					return fmt.Errorf("label %q is not claimed", args[0])
				}
				return fmt.Errorf("%w (socket %s)", err, path)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "label %s released\n", args[0])
			return nil
		},
	}
}
