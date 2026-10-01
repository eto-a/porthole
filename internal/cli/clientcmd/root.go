// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package clientcmd implements the command line of the porthole client binary.
package clientcmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/daemon"
	"github.com/eto-a/porthole/internal/localapi"
)

// envSocket selects the daemon socket (below --socket, above the default locations).
const envSocket = "PORTHOLE_SOCKET"

// apiClient is the part of *localapi.Client the commands use; tests replace it.
type apiClient interface {
	Status(ctx context.Context) (localapi.Status, error)
	Tunnels(ctx context.Context) ([]localapi.Tunnel, error)
	AddTunnel(ctx context.Context, req localapi.AddTunnelRequest) (localapi.Tunnel, error)
	RemoveTunnel(ctx context.Context, name string) error
	Reload(ctx context.Context) (localapi.ReloadResult, error)
	Attach(ctx context.Context, req localapi.AddTunnelRequest, fn func(localapi.Event) error) error
	Close()
}

// deps are the process-level dependencies of the commands; tests replace them. A nil socketPaths or userSocket
// means "none", so a test that does not set them never talks to a real daemon.
type deps struct {
	run           func(ctx context.Context, opts client.Options) error
	check         func(ctx context.Context, opts client.Options) (client.CheckResult, error)
	getenv        func(string) string
	userConfigDir func() (string, error)
	currentUser   func() string // user name for the printed ssh command

	socketPaths func() []string                                      // where to look for a daemon, in order
	userSocket  func() string                                        // the socket `porthole daemon` creates by default
	dial        func(socketPath string) apiClient                    // a client of the local API at socketPath
	runDaemon   func(ctx context.Context, opts daemon.Options) error // `porthole daemon`

	// detachTimeout bounds how long `--detach` waits for the tunnel to become ready; zero means the default.
	detachTimeout time.Duration
}

func defaultDeps() deps {
	return deps{
		run:           client.Run,
		check:         client.Check,
		getenv:        os.Getenv,
		userConfigDir: os.UserConfigDir,
		currentUser:   osUser,

		socketPaths: localapi.DefaultSocketPaths,
		userSocket:  localapi.UserSocketPath,
		dial:        func(p string) apiClient { return localapi.NewClient(p) },
		runDaemon: func(ctx context.Context, opts daemon.Options) error {
			d, err := daemon.New(opts)
			if err != nil {
				return err
			}
			return d.Run(ctx)
		},
	}
}

// app carries the state shared by all commands of one NewRoot call (there is no package-level state).
type app struct {
	d          deps
	version    string
	configPath string // --config
	socket     string // --socket
	verbose    bool   // --verbose
}

// NewRoot returns the root command of the porthole client.
func NewRoot(version string) *cobra.Command {
	return newRoot(version, defaultDeps())
}

func newRoot(version string, d deps) *cobra.Command {
	a := &app{d: d, version: version}
	root := &cobra.Command{
		Use:   "porthole",
		Short: "Expose local services through a porthole server",
		Long: "porthole exposes local HTTP and TCP services (and ssh) through a self-hosted porthole server.\n\n" +
			"Run `porthole login <server-url> <token>` once, then e.g. `porthole http 8080`.\n\n" +
			"For tunnels that should stay up, list them in a tunnels file and run `porthole daemon` (or the system " +
			"service); `porthole status`, `reload`, `close` and the tunnel commands then talk to that daemon.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.configPath, "config", "", "config file (default: <user config dir>/porthole/config.yaml)")
	root.PersistentFlags().StringVar(&a.socket, "socket", "",
		"socket of the porthole daemon (default: $"+envSocket+", then the user socket, then the system socket)")
	root.PersistentFlags().BoolVarP(&a.verbose, "verbose", "v", false, "verbose logging")
	jsonout.AddFlag(root)

	root.AddCommand(
		a.newLoginCmd(),
		a.newJoinCmd(),
		a.newHTTPCmd(),
		a.newTCPCmd(),
		a.newSSHCmd(),
		a.newStartCmd(),
		a.newDaemonCmd(),
		a.newStatusCmd(),
		a.newTunnelsCmd(),
		a.newReloadCmd(),
		a.newCloseCmd(),
		a.newMCPCmd(),
		a.newVersionCmd(),
	)
	return root
}

func (a *app) newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the porthole version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if jsonout.Enabled(cmd) {
				return jsonout.Write(cmd.OutOrStdout(), map[string]string{
					"name": "porthole", "version": a.version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
				})
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "porthole %s (%s, %s/%s)\n", a.version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return err
		},
	}
}

func (a *app) logger(cmd *cobra.Command) *slog.Logger {
	level := slog.LevelWarn
	if a.verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: level}))
}

func (a *app) path() (string, error) {
	if a.configPath != "" {
		return a.configPath, nil
	}
	return defaultConfigPath(a.d.userConfigDir)
}
