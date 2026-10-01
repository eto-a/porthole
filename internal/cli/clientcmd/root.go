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

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/client"
)

// deps are the process-level dependencies of the commands; tests replace them.
type deps struct {
	run           func(ctx context.Context, opts client.Options) error
	check         func(ctx context.Context, opts client.Options) (client.CheckResult, error)
	getenv        func(string) string
	userConfigDir func() (string, error)
	currentUser   func() string // user name for the printed ssh command
}

func defaultDeps() deps {
	return deps{
		run:           client.Run,
		check:         client.Check,
		getenv:        os.Getenv,
		userConfigDir: os.UserConfigDir,
		currentUser:   osUser,
	}
}

// app carries the state shared by all commands of one NewRoot call (there is no package-level state).
type app struct {
	d          deps
	version    string
	configPath string // --config
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
			"Run `porthole login <server-url> <token>` once, then e.g. `porthole http 8080`.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.configPath, "config", "", "config file (default: <user config dir>/porthole/config.yaml)")
	root.PersistentFlags().BoolVarP(&a.verbose, "verbose", "v", false, "verbose logging")

	root.AddCommand(
		a.newLoginCmd(),
		a.newHTTPCmd(),
		a.newTCPCmd(),
		a.newSSHCmd(),
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
