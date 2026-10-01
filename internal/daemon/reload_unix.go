// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package daemon

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// reloadTimeout bounds a reload triggered by SIGHUP.
const reloadTimeout = 30 * time.Second

// watchReload reloads the tunnels file on SIGHUP (systemctl reload sends it when the unit has no ExecReload) until
// ctx is done.
func (d *Daemon) watchReload(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			d.reloadFromSignal(ctx)
		}
	}
}

// reloadFromSignal is a reload not requested over the API: the result is only logged.
func (d *Daemon) reloadFromSignal(ctx context.Context) {
	d.log.Info("reload requested by signal")
	rctx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()
	if _, err := d.Reload(rctx); err != nil {
		d.log.Warn("reload failed, keeping the current tunnels", "err", err)
	}
}
