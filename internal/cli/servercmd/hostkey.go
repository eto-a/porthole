// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/server"
)

// NewHostKey returns the `ssh-hostkey` command: it prints the SHA256 fingerprint of the SSH gateway host key so the
// user can compare it with the one ssh shows on the first connection through the gateway.
func NewHostKey(load func() (*config.Config, error)) *cobra.Command {
	return &cobra.Command{
		Use:           "ssh-hostkey",
		Short:         "Print the fingerprint of the SSH gateway host key",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			fp, err := server.HostKeyFingerprint(cfg.DataDir)
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("no host key at %s yet: start portholed with ssh_gateway.listen set, it creates the key on first start",
					filepath.Join(cfg.DataDir, server.HostKeyFile))
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), fp)
			return nil
		},
	}
}
