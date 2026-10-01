// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package servercmd provides the `portholed serve` command.
package servercmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/server"
	"github.com/eto-a/porthole/internal/store"
)

// NewServe returns the `serve` command. load produces the validated configuration (the caller decides where it
// comes from: file, environment, flags); openStore opens the persistent store for it.
func NewServe(
	load func() (*config.Config, error),
	openStore func(ctx context.Context, cfg *config.Config) (store.Store, error),
	version string,
) *cobra.Command {
	var logLevel string
	cmd := &cobra.Command{
		Use:           "serve",
		Short:         "Run the porthole server",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			level, err := parseLevel(logLevel)
			if err != nil {
				return err
			}
			logger := slog.New(slog.NewJSONHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: level}))

			cfg, err := load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			parent := cmd.Context()
			if parent == nil {
				parent = context.Background()
			}
			ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
			defer stop()

			st, err := openStore(ctx, cfg)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() {
				if err := st.Close(); err != nil {
					logger.Warn("closing store failed", "err", err)
				}
			}()

			srv, err := server.New(server.Options{
				Config:  cfg,
				Store:   st,
				Logger:  logger,
				Version: version,
			})
			if err != nil {
				return err
			}
			stopReload := watchReload(ctx, logger, srv.ReloadTLS)
			defer stopReload()
			logger.Info("portholed starting",
				"version", version,
				"domain", cfg.Domain,
				"listen", cfg.Listen,
				"tls", cfg.TLS.Enabled(),
				"tcp_port_range", cfg.TCPPortRange,
			)
			if err := srv.Run(ctx); err != nil {
				return err
			}
			logger.Info("portholed stopped")
			return nil
		},
	}
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn or error")
	return cmd
}

func parseLevel(s string) (slog.Level, error) {
	var l slog.Level
	switch s {
	case "debug", "info", "warn", "error":
		if err := l.UnmarshalText([]byte(s)); err != nil {
			return 0, fmt.Errorf("invalid --log-level %q: %w", s, err)
		}
		return l, nil
	}
	return 0, errors.New(`invalid --log-level "` + s + `": want debug, info, warn or error`)
}
