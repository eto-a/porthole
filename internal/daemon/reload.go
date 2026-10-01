// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"time"
)

// reloadTimeout bounds a reload that was not requested over the API (SIGHUP, or the service manager).
const reloadTimeout = 30 * time.Second

// reloadFromRequest is a reload not requested over the API: the result is only logged. why names the trigger.
func (d *Daemon) reloadFromRequest(ctx context.Context, why string) {
	d.log.Info("reload requested", "by", why)
	rctx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()
	if _, err := d.Reload(rctx); err != nil {
		d.log.Warn("reload failed, keeping the current tunnels", "err", err)
	}
}
