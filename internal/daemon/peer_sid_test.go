// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"testing"

	"github.com/eto-a/porthole/internal/localapi"
)

// winPeer is a context as the local API handler builds it for a Windows named-pipe caller: no uid, an SID.
func winPeer(sid string) context.Context {
	return localapi.WithPeerCred(context.Background(), localapi.Cred{UID: -1, GID: -1, PID: 1, SID: sid})
}

const aliceSID = "S-1-5-21-1-2-3-1001"

// A Windows caller that is allowed on the pipe but is not an administrator, SYSTEM or the daemon's own account is
// an unprivileged peer, the twin of the porthole-client group on Linux (see ADR 0006).
func TestWindowsPeerIsUnprivilegedByDefault(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, twoTunnels)
	h.waitReady("blog", "db")

	_, err := h.d.AddTunnel(winPeer(aliceSID), localapi.AddTunnelRequest{Type: "tcp", Name: "x", Addr: "192.168.1.1:80", Lifetime: localapi.LifetimeRuntime})
	_ = apiErr(t, err, localapi.CodeForbidden)
	_, err = h.d.Reload(winPeer(aliceSID))
	_ = apiErr(t, err, localapi.CodeForbidden)

	if _, err := h.d.AddTunnel(winPeer(aliceSID), localapi.AddTunnelRequest{Type: "http", Name: "a", Addr: "3000", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Fatalf("loopback target: %v", err)
	}
	_ = apiErr(t, h.d.RemoveTunnel(winPeer("S-1-5-21-1-2-3-1002"), "a"), localapi.CodeForbidden)
	_ = apiErr(t, h.d.RemoveTunnel(winPeer(aliceSID), "blog"), localapi.CodeConflict) // file tunnels are never removable
	if err := h.d.RemoveTunnel(winPeer(aliceSID), "a"); err != nil {
		t.Fatalf("owner: %v", err)
	}
}

func TestWindowsPeerTrust(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\n")
	const self = "S-1-5-21-1-2-3-1000"
	h.d.selfSID = self

	cred := func(sid string, admin bool) context.Context {
		return localapi.WithPeerCred(context.Background(), localapi.Cred{UID: -1, GID: -1, PID: 1, SID: sid, Admin: admin})
	}
	for name, ctx := range map[string]context.Context{
		"SYSTEM":         cred("S-1-5-18", false),
		"the daemon SID": cred(self, false),
		"administrator":  cred(aliceSID, true),
	} {
		if _, err := h.d.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "tcp", Name: "t", Addr: "192.168.1.1:80", Lifetime: localapi.LifetimeRuntime}); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if _, err := h.d.Reload(ctx); err != nil {
			t.Errorf("%s reload: %v", name, err)
		}
		if err := h.d.RemoveTunnel(cred("S-1-5-21-1-2-3-1999", true), "t"); err != nil {
			t.Errorf("%s: an administrator cannot remove the tunnel: %v", name, err)
		}
	}

	// A pipe client whose SID could not be read is not trusted and owns nothing, whatever else it claims.
	for _, ctx := range []context.Context{cred("", false), cred("", true)} {
		_, err := h.d.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "tcp", Name: "u", Addr: "192.168.1.1:80", Lifetime: localapi.LifetimeRuntime})
		_ = apiErr(t, err, localapi.CodeForbidden)
		_, err = h.d.Reload(ctx)
		_ = apiErr(t, err, localapi.CodeForbidden)
	}
	if _, err := h.d.AddTunnel(cred("", false), localapi.AddTunnelRequest{Type: "http", Name: "l", Addr: "3000", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Fatal(err)
	}
	_ = apiErr(t, h.d.RemoveTunnel(cred("", false), "l"), localapi.CodeForbidden) // no owner to match
}
