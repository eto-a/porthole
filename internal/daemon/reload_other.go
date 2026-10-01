// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package daemon

import "context"

// watchReload reloads the tunnels file on a value of Options.Reload (on Windows `sc control porthole paramchange`,
// the twin of SIGHUP) until ctx is done. There is no signal here; `porthole reload` works as everywhere.
func (d *Daemon) watchReload(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.opts.Reload:
			d.reloadFromRequest(ctx, "the service manager")
		}
	}
}
