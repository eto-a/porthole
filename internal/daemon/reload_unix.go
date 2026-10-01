// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package daemon

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// watchReload reloads the tunnels file on SIGHUP (systemctl reload sends it when the unit has no ExecReload) and on
// a value of Options.Reload, until ctx is done.
func (d *Daemon) watchReload(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			d.reloadFromRequest(ctx, "signal")
		case <-d.opts.Reload:
			d.reloadFromRequest(ctx, "the service manager")
		}
	}
}
