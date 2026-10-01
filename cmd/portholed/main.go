// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Command portholed is the porthole server.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/servercmd"
	"github.com/eto-a/porthole/internal/cli/tokencmd"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := newRoot().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	var configPath string
	root := &cobra.Command{
		Use:           "portholed",
		Short:         "porthole server: exposes tunnels opened by porthole clients",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/porthole/portholed.yaml",
		"path to the configuration file (empty to use only PORTHOLED_* variables)")

	load := func() (*config.Config, error) { return config.Load(configPath) }
	openStore := func(ctx context.Context, cfg *config.Config) (store.Store, error) {
		return store.Open(ctx, cfg.DBPath())
	}

	root.AddCommand(
		servercmd.NewServe(load, openStore, version),
		tokencmd.New(load),
		&cobra.Command{
			Use:   "version",
			Short: "Print the version",
			Args:  cobra.NoArgs,
			Run: func(cmd *cobra.Command, _ []string) {
				fmt.Fprintln(cmd.OutOrStdout(), "portholed", version)
			},
		},
	)
	return root
}
