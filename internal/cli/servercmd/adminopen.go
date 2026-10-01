// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
)

// openCallTimeout covers the server's wait for the client (15 s) with a margin.
const openCallTimeout = 25 * time.Second

// openedJSON is the --json document of `admin open`.
type openedJSON struct {
	Client string `json:"client"`
	adminapi.RemoteTunnel
}

// newAdminOpen returns `admin open`: ask a connected client to open a tunnel on its machine (ADR 0005).
func newAdminOpen(load func() (*config.Config, error), socket *string) *cobra.Command {
	var (
		name       string
		private    bool
		remotePort int
	)
	cmd := &cobra.Command{
		Use:   "open <client> <http|tcp|ssh> [local]",
		Short: "Ask a connected client to open a tunnel and print its address",
		Long: "Ask the connected client to open a tunnel to a local target on its machine: a port, host:port, or\n" +
			"(for ssh) nothing, which means 127.0.0.1:22. The client must run the porthole daemon, accept remote\n" +
			"requests (allow_remote in its tunnels.yaml) and its token must allow remote control.",
		Example: "  portholed admin open home http 3000\n  portholed admin open home ssh --private\n  portholed admin open home tcp 192.168.1.5:80 --json",
		Args:    cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := adminSocketPath(load, *socket)
			if err != nil {
				return err
			}
			req := adminapi.RemoteOpen{Kind: args[1], Name: name, Private: private, RemotePort: remotePort}
			if len(args) == 3 {
				req.LocalAddr = args[2]
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), openCallTimeout)
			defer cancel()
			tun, err := adminapi.NewSocketClient(path).RequestTunnel(ctx, args[0], req)
			if err != nil {
				return openError(err, path)
			}
			out := cmd.OutOrStdout()
			if jsonout.Enabled(cmd) {
				return jsonout.Write(out, openedJSON{Client: args[0], RemoteTunnel: tun})
			}
			fmt.Fprintf(out, "tunnel %q (%s) is open on %s: %s\n", tun.Name, tun.Kind, args[0], tun.URL)
			if tun.SSHJump != "" {
				fmt.Fprintf(out, "ssh gateway: %s\n", tun.SSHJump)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "tunnel name (default: from the kind and port)")
	cmd.Flags().BoolVar(&private, "private", false, "ssh only: the gateway requires a porthole token")
	cmd.Flags().IntVar(&remotePort, "remote-port", 0, "tcp only: ask for this public port")
	return cmd
}

// openError turns an API failure into a command error. A refusal of the request itself (the client, its policy or
// the server's limits said no) exits with exitcode.Rejected, like a refused tunnel.
func openError(err error, socket string) error {
	var ae *adminapi.Error
	if !errors.As(err, &ae) {
		return fmt.Errorf("%w (socket %s; is portholed running and the socket readable by you?)", err, socket)
	}
	msg := ae.Message
	if ae.Code == "not_found" {
		msg = "no such client is connected"
	}
	wrapped := fmt.Errorf("%s: %s", ae.Code, strings.TrimSpace(msg))
	switch ae.Code {
	case proto.CodeNameTaken, proto.CodeForbidden, proto.CodeLimitExceeded, proto.CodePortUnavailable,
		proto.CodeNotAllowed, adminapi.CodeRemoteDisabled, proto.CodeClientUnsupported:
		return &exitcode.Error{Code: exitcode.Rejected, Err: wrapped}
	}
	return wrapped
}
