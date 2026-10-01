// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/client"
)

const checkTimeout = 30 * time.Second

func (a *app) newLoginCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "login <server-url> <token>",
		Short: "Store the server URL and token",
		Long: "Store the server URL and token in the client config file (mode 0600).\n" +
			"The $" + envServer + " and $" + envToken + " variables and the --server and --token flags of the tunnel commands\n" +
			"override the stored values.",
		Example: "  porthole login https://tun.example.com ph_3kq9w2m1z8xa_...",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			server := strings.TrimRight(strings.TrimSpace(args[0]), "/")
			token := strings.TrimSpace(args[1])
			if _, err := client.ConnectURL(server); err != nil {
				return err
			}
			if _, err := auth.Parse(token); err != nil {
				return errors.New("invalid token: expected the form ph_<id>_<secret>")
			}
			path, err := a.path()
			if err != nil {
				return err
			}
			if err := saveConfig(path, fileConfig{Server: server, Token: token}); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Saved credentials for %s to %s\n", server, path)

			if !check {
				return nil
			}
			parent := cmd.Context()
			if parent == nil {
				parent = context.Background()
			}
			ctx, cancel := context.WithTimeout(parent, checkTimeout)
			defer cancel()
			res, err := a.d.check(ctx, client.Options{
				ServerURL: server,
				Token:     token,
				Version:   a.version,
				Logger:    a.logger(cmd),
			})
			if err != nil {
				return fmt.Errorf("credentials saved, but the server check failed: %w", explain(err))
			}
			fmt.Fprintf(out, "Server check passed: logged in as %q (server version %s)\n", res.ClientName, res.ServerVersion)
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "connect to the server and verify the token")
	return cmd
}
