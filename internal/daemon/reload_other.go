// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package daemon

import "context"

// watchReload does nothing: there is no SIGHUP here. Use `porthole reload`.
func (d *Daemon) watchReload(context.Context) {}
