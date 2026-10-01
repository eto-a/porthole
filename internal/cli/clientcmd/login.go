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
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/client"
)

const checkTimeout = 30 * time.Second

// loginResult is the --json output of `porthole login`. It never contains the token.
type loginResult struct {
	Saved  bool        `json:"saved"`
	Server string      `json:"server"`
	Config string      `json:"config"` // path of the file the credentials were written to
	Check  *loginCheck `json:"check,omitempty"`
}

// loginCheck is what `porthole login --check` learned from the server.
type loginCheck struct {
	ClientName    string `json:"client_name"`
	ServerVersion string `json:"server_version"`
}

func (a *app) newLoginCmd() *cobra.Command {
	var check, system bool
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
				return usageErr(err)
			}
			if _, err := auth.Parse(token); err != nil {
				return usageErr(errors.New("invalid token: expected the form ph_<id>_<secret>"))
			}
			path, err := a.configTarget(system)
			if err != nil {
				return err
			}
			warnPlaintext(cmd, server)
			if err := saveConfig(path, fileConfig{Server: server, Token: token}); err != nil {
				return err
			}
			a.afterSystemSave(cmd, system, path)
			out := cmd.OutOrStdout()
			asJSON := jsonout.Enabled(cmd)
			if !asJSON {
				fmt.Fprintf(out, "Saved credentials for %s to %s\n", server, path)
			}
			result := loginResult{Saved: true, Server: server, Config: path}

			if !check {
				if asJSON {
					return jsonout.Write(out, result)
				}
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
			if asJSON {
				result.Check = &loginCheck{ClientName: res.ClientName, ServerVersion: res.ServerVersion}
				return jsonout.Write(out, result)
			}
			fmt.Fprintf(out, "Server check passed: logged in as %q (server version %s)\n", res.ClientName, res.ServerVersion)
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "connect to the server and verify the token")
	cmd.Flags().BoolVar(&system, "system", false, "write the config file of the system service (needs root or Administrator) instead of your own")
	return cmd
}
