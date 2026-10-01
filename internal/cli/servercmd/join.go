// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/config"
)

const joinTimeLayout = "2006-01-02 15:04"

// NewJoin returns the `join` command group: one-time join links, managed through the running server's admin socket
// (ADR 0005). Access to the socket is the permission, as for `admin`.
func NewJoin(load func() (*config.Config, error)) *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Create, list and revoke one-time join links",
		Long: "A join link enrols a machine without anyone copying a token: the machine runs `porthole join <link>` once\n" +
			"and receives its own permanent token. Links are single use and expire after 15 minutes by default.\n" +
			"The commands talk to the running server over its admin socket.",
	}
	cmd.PersistentFlags().StringVar(&socket, "socket", "", "admin socket path (default: from the configuration)")
	client := func(*cobra.Command) (*adminapi.SocketClient, string, error) {
		path, err := adminSocketPath(load, socket)
		if err != nil {
			return nil, "", exitcode.ConfigError(err)
		}
		return adminapi.NewSocketClient(path), path, nil
	}
	cmd.AddCommand(joinCreateCmd(client), joinListCmd(client), joinRevokeCmd(client))
	return cmd
}

type clientFn func(cmd *cobra.Command) (*adminapi.SocketClient, string, error)

func socketHint(err error, path string) error {
	var ae *adminapi.Error
	if errors.As(err, &ae) {
		return err
	}
	return fmt.Errorf("%w (socket %s; is portholed running and the socket readable by you?)", err, path)
}

func joinCreateCmd(client clientFn) *cobra.Command {
	var (
		req      adminapi.JoinRequest
		noRemote bool
	)
	cmd := &cobra.Command{
		Use:   "create --name <name>",
		Short: "Create a one-time join link",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, path, err := client(cmd)
			if err != nil {
				return err
			}
			if noRemote {
				off := false
				req.RemoteControl = &off
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), adminCallTimeout)
			defer cancel()
			res, err := c.CreateJoin(ctx, req)
			if err != nil {
				return socketHint(err, path)
			}
			out := cmd.OutOrStdout()
			if jsonout.Enabled(cmd) {
				return jsonout.Write(out, res)
			}
			fmt.Fprintf(out, "Join link for %q (id %s), valid until %s UTC and usable once.\n\n", res.ClientName, res.ID,
				res.ExpiresAt.UTC().Format(joinTimeLayout))
			fmt.Fprintf(out, "On the machine, run:\n\n    %s\n\n", res.Command)
			fmt.Fprintln(out, "The link is shown only now: the server keeps just a hash of its code.")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&req.ClientName, "name", "", "client name, becomes part of tunnel URLs (required)")
	f.StringVar(&req.TTL, "ttl", "", "how long the link works: 15m (default), 2h, 1d; at most 7d")
	f.StringSliceVar(&req.Scopes, "scopes", nil, "comma-separated scopes of the new token (default: tunnel:http,tunnel:tcp,tunnel:udp)")
	f.IntVar(&req.MaxTunnels, "max-tunnels", 0, "maximum simultaneous tunnels (0 = server default)")
	f.StringVar(&req.TokenExpiresIn, "expires", "", "lifetime of the token the link creates: 30d, 720h; default no expiry")
	f.BoolVar(&noRemote, "no-remote-control", false, "do not let operators open tunnels on this machine remotely")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func joinListCmd(client clientFn) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List join links",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, path, err := client(cmd)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), adminCallTimeout)
			defer cancel()
			codes, err := c.ListJoin(ctx)
			if err != nil {
				return socketHint(err, path)
			}
			out := cmd.OutOrStdout()
			if jsonout.Enabled(cmd) {
				if codes == nil {
					codes = []adminapi.JoinCode{}
				}
				return jsonout.Write(out, map[string]any{"join_codes": codes})
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tSTATUS\tEXPIRES\tSCOPES\tREMOTE")
			for i := range codes {
				j := &codes[i]
				if j.Status != "active" && !all {
					continue
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%t\n", j.ID, j.ClientName, j.Status,
					j.ExpiresAt.UTC().Format(joinTimeLayout), strings.Join(j.Scopes, ","), j.RemoteControl)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "include used, revoked and expired links")
	return cmd
}

func joinRevokeCmd(client clientFn) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an unused join link",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, path, err := client(cmd)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), adminCallTimeout)
			defer cancel()
			if err := c.RevokeJoin(ctx, args[0]); err != nil {
				return socketHint(err, path)
			}
			if jsonout.Enabled(cmd) {
				return jsonout.Write(cmd.OutOrStdout(), map[string]any{"id": args[0], "revoked": true})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Revoked join link %s.\n", args[0])
			return nil
		},
	}
}
