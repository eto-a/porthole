// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/localapi"
)

// withDaemon connects to the daemon and runs fn with a context bounded by callTimeout.
func (a *app) withDaemon(cmd *cobra.Command, fn func(ctx context.Context, cl apiClient, socket string) error) error {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	cl, socket, err := a.requireDaemon(parent)
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(parent, callTimeout)
	defer cancel()
	return fn(ctx, cl, socket)
}

func (a *app) newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the state of the porthole daemon and its tunnels",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.withDaemon(cmd, func(ctx context.Context, cl apiClient, socket string) error {
				st, err := cl.Status(ctx)
				if err != nil {
					return apiErr(err, socket)
				}
				if st.Tunnels == nil {
					st.Tunnels = []localapi.Tunnel{}
				}
				if jsonout.Enabled(cmd) {
					return jsonout.Write(cmd.OutOrStdout(), st)
				}
				printStatus(cmd.OutOrStdout(), st, socket)
				return nil
			})
		},
	}
	return cmd
}

func (a *app) newTunnelsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tunnels",
		Aliases: []string{"ls"},
		Short:   "List the tunnels of the porthole daemon",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.withDaemon(cmd, func(ctx context.Context, cl apiClient, socket string) error {
				ts, err := cl.Tunnels(ctx)
				if err != nil {
					return apiErr(err, socket)
				}
				if ts == nil {
					ts = []localapi.Tunnel{}
				}
				if jsonout.Enabled(cmd) {
					return jsonout.Write(cmd.OutOrStdout(), ts)
				}
				printTunnels(cmd.OutOrStdout(), ts)
				return nil
			})
		},
	}
	return cmd
}

func (a *app) newReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Make the daemon re-read its tunnels file",
		Long: "Make the daemon re-read its tunnels file and apply the difference: new tunnels are registered, removed ones " +
			"are closed, changed ones are registered again, the rest is not touched. A file that is not valid is " +
			"rejected as a whole and the daemon keeps what it has.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.withDaemon(cmd, func(ctx context.Context, cl apiClient, socket string) error {
				res, err := cl.Reload(ctx)
				if err != nil {
					return apiErr(err, socket)
				}
				if jsonout.Enabled(cmd) {
					return writeReloadJSON(cmd.OutOrStdout(), res)
				}
				return printReload(cmd.OutOrStdout(), cmd.ErrOrStderr(), res)
			})
		},
	}
}

func (a *app) newCloseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "close <name>",
		Short: "Remove a tunnel from the daemon",
		Long: "Remove a runtime tunnel (added with `porthole http --detach` and the like) from the daemon. Tunnels of the " +
			"tunnels file are removed by editing the file and running `porthole reload`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withDaemon(cmd, func(ctx context.Context, cl apiClient, socket string) error {
				if err := cl.RemoveTunnel(ctx, args[0]); err != nil {
					return apiErr(err, socket)
				}
				if jsonout.Enabled(cmd) {
					return jsonout.Write(cmd.OutOrStdout(), struct {
						Closed string `json:"closed"`
					}{args[0]})
				}
				fmt.Fprintf(cmd.OutOrStdout(), "closed %s\n", args[0])
				return nil
			})
		},
	}
}

// writeReloadJSON writes the outcome of a reload as one JSON object (see localapi.ReloadResult). Per-tunnel failures
// are in "errors" and make the command fail with exit status 5; no second document follows.
func writeReloadJSON(w io.Writer, res localapi.ReloadResult) error {
	for _, list := range []*[]string{&res.Added, &res.Removed, &res.Changed, &res.Unchanged} {
		if *list == nil {
			*list = []string{}
		}
	}
	if err := jsonout.Write(w, res); err != nil {
		return err
	}
	if len(res.Errors) > 0 {
		return &ExitError{Code: exitcode.Rejected, Err: errReloadFailed, Quiet: true}
	}
	return nil
}

var errReloadFailed = errors.New("the reload finished with errors")

// printStatus renders the daemon status for people.
func printStatus(w io.Writer, st localapi.Status, socket string) {
	fmt.Fprintf(w, "daemon:  pid %d, up %s, porthole %s (socket %s)\n",
		st.PID, time.Since(st.StartedAt).Round(time.Second), st.Version, socket)
	switch st.State {
	case localapi.StateConnected:
		fmt.Fprintf(w, "server:  %s, connected as %s\n", st.Server, st.ClientName)
	case localapi.StateBackoff:
		line := fmt.Sprintf("server:  %s, not connected", st.Server)
		if st.RetryAt != nil {
			line += fmt.Sprintf(", retrying in %ds", max(0, int((time.Until(*st.RetryAt)+time.Second-1)/time.Second)))
		}
		if st.LastError != "" {
			line += ": " + st.LastError
		}
		fmt.Fprintln(w, line)
	default:
		fmt.Fprintf(w, "server:  %s, %s\n", st.Server, st.State)
	}
	if st.TunnelsFile != "" {
		fmt.Fprintf(w, "file:    %s\n", st.TunnelsFile)
	}
	fmt.Fprintln(w)
	printTunnels(w, st.Tunnels)
}

// printTunnels renders a table of tunnels. The error of a failed tunnel follows the table.
func printTunnels(w io.Writer, ts []localapi.Tunnel) {
	if len(ts) == 0 {
		fmt.Fprintln(w, "no tunnels")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tLOCAL\tPUBLIC\tSTATE\tLIFETIME")
	for i := range ts {
		t := &ts[i]
		pub := t.PublicURL
		if pub == "" {
			pub = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.Name, t.Type, t.LocalAddr, pub, t.State, t.Lifetime)
	}
	_ = tw.Flush()
	for i := range ts {
		if ts[i].Error != "" {
			fmt.Fprintf(w, "%s: %s\n", ts[i].Name, ts[i].Error)
		}
	}
}

// printReload renders the outcome of a reload. Per-tunnel failures go to errOut and make the command fail.
func printReload(out, errOut io.Writer, res localapi.ReloadResult) error {
	fmt.Fprintf(out, "reloaded: %d added, %d removed, %d changed, %d unchanged\n",
		len(res.Added), len(res.Removed), len(res.Changed), len(res.Unchanged))
	for _, g := range []struct {
		label string
		names []string
	}{{"added", res.Added}, {"removed", res.Removed}, {"changed", res.Changed}} {
		if len(g.names) > 0 {
			fmt.Fprintf(out, "  %s: %s\n", g.label, strings.Join(g.names, ", "))
		}
	}
	if len(res.Errors) == 0 {
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(res.Errors)) {
		fmt.Fprintf(errOut, "tunnel %s: %s\n", name, res.Errors[name])
	}
	return &ExitError{Code: exitcode.Rejected, Err: errReloadFailed}
}
