// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"testing"

	"github.com/eto-a/porthole/internal/localapi"
)

// A value on Options.Reload (the Windows service control manager's ParamChange) reloads the tunnels file; a broken
// file keeps the set.
func TestReloadChannelReloadsTheFile(t *testing.T) {
	fs := newFakeServer(t)
	reload := make(chan struct{}, 1)
	h := startDaemon(t, fs, "version: 1\n", func(o *Options) { o.Reload = reload })

	h.writeFile("version: 1\ntunnels:\n  blog: {type: http, addr: 3000}\n")
	reload <- struct{}{}
	waitFor(t, "blog to appear after a reload request", func() bool { return h.tunnels()["blog"].State == localapi.TunnelReady })

	h.writeFile("{{{")
	reload <- struct{}{}
	waitFor(t, "the broken file to be rejected", func() bool { return h.tunnels()["blog"].State == localapi.TunnelReady })
	if _, err := h.cl.Reload(t.Context()); err == nil {
		t.Error("the broken file was accepted")
	}
}
