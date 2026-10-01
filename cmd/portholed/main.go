// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Command portholed is the porthole server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/cli/servercmd"
	"github.com/eto-a/porthole/internal/cli/tokencmd"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := exitcode.Run(ctx, newRoot(), "portholed", os.Args[1:], nil)
	stop()
	os.Exit(code)
}

func newRoot() *cobra.Command {
	var configPath string
	root := &cobra.Command{
		Use:           "portholed",
		Short:         "porthole server: exposes tunnels opened by porthole clients",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/porthole/portholed.yaml",
		"path to the configuration file (empty to use only PORTHOLED_* variables)")

	jsonout.AddFlag(root)

	load := func() (*config.Config, error) { return config.Load(configPath) }
	openStore := func(ctx context.Context, cfg *config.Config) (store.Store, error) {
		return store.Open(ctx, cfg.DBPath())
	}

	root.AddCommand(
		servercmd.NewServe(load, openStore, version),
		servercmd.NewHostKey(load),
		tokencmd.New(load),
		&cobra.Command{
			Use:   "version",
			Short: "Print the version",
			Args:  cobra.NoArgs,
			Run: func(cmd *cobra.Command, _ []string) {
				if jsonout.Enabled(cmd) {
					_ = jsonout.Write(cmd.OutOrStdout(), map[string]string{
						"name": "portholed", "version": version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
					})
					return
				}
				fmt.Fprintln(cmd.OutOrStdout(), "portholed", version)
			},
		},
	)
	return root
}
