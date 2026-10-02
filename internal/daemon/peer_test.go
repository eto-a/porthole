// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/eto-a/porthole/internal/localapi"
)

// peer returns a context as the local API handler would build it for a caller with the given uid.
func peer(uid int) context.Context {
	return localapi.WithPeerCred(context.Background(), localapi.Cred{UID: uid, GID: uid, PID: 1})
}

// selfPeer is a context for the account the daemon itself runs as: its uid on Unix, its SID on Windows.
func selfPeer(h *harness) context.Context {
	if uid := os.Geteuid(); uid >= 0 {
		return peer(uid)
	}
	return winPeer(h.d.selfSID)
}

// otherUID is a uid that is neither root nor the daemon's.
func otherUID(not ...int) int {
	uid := 54321
	for slices.Contains(not, uid) || uid == os.Geteuid() {
		uid++
	}
	return uid
}

func TestLocalAPIPeerTargetPolicy(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\n")
	user := otherUID()

	for _, addr := range []string{"192.168.1.1:80", "169.254.169.254:80", "nas.local:80", "10.0.0.5:5432"} {
		_, err := h.d.AddTunnel(peer(user), localapi.AddTunnelRequest{Type: "tcp", Name: "x", Addr: addr, Lifetime: localapi.LifetimeRuntime})
		_ = apiErr(t, err, localapi.CodeForbidden)
	}
	if n := len(h.tunnels()); n != 0 {
		t.Fatalf("%d tunnels were added despite the refusals", n)
	}

	// Loopback is fine for an unprivileged peer.
	if _, err := h.d.AddTunnel(peer(user), localapi.AddTunnelRequest{Type: "http", Name: "dev", Addr: "3000", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Fatal(err)
	}
	// root and the daemon's own user may publish anything (the allow_remote policy is not applied to them).
	for name, ctx := range map[string]context.Context{"root": peer(0), "self": selfPeer(h)} {
		if _, err := h.d.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "tcp", Name: name, Addr: "192.168.1.1:80", Lifetime: localapi.LifetimeRuntime}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A caller without credentials (no SO_PEERCRED on this platform) behaves as before.
	if _, err := h.d.AddTunnel(context.Background(), localapi.AddTunnelRequest{Type: "tcp", Name: "nocred", Addr: "192.168.1.2:80", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Errorf("no credentials: %v", err)
	}
}

func TestLocalAPIPeerFollowsAllowRemote(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\nallow_remote: [\"192.168.1.1:80\"]\n")
	user := otherUID()
	if _, err := h.d.AddTunnel(peer(user), localapi.AddTunnelRequest{Type: "tcp", Name: "router", Addr: "192.168.1.1:80", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Fatalf("listed target: %v", err)
	}
	_, err := h.d.AddTunnel(peer(user), localapi.AddTunnelRequest{Type: "tcp", Name: "other", Addr: "192.168.1.2:80", Lifetime: localapi.LifetimeRuntime})
	_ = apiErr(t, err, localapi.CodeForbidden)
}

func TestLocalAPIPeerOwnership(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, twoTunnels)
	h.waitReady("blog", "db")
	alice := otherUID()
	bob := otherUID(alice)

	if _, err := h.d.AddTunnel(peer(alice), localapi.AddTunnelRequest{Type: "http", Name: "a", Addr: "3000", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Fatal(err)
	}
	// Another unprivileged user cannot close it, root, the daemon user and the owner can.
	_ = apiErr(t, h.d.RemoveTunnel(peer(bob), "a"), localapi.CodeForbidden)
	if _, ok := h.tunnels()["a"]; !ok {
		t.Fatal("the tunnel of another user was closed")
	}
	if err := h.d.RemoveTunnel(peer(alice), "a"); err != nil {
		t.Fatalf("owner: %v", err)
	}
	if _, err := h.d.AddTunnel(peer(alice), localapi.AddTunnelRequest{Type: "http", Name: "a", Addr: "3000", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Fatal(err)
	}
	if err := h.d.RemoveTunnel(peer(0), "a"); err != nil {
		t.Fatalf("root: %v", err)
	}
	if _, err := h.d.AddTunnel(peer(alice), localapi.AddTunnelRequest{Type: "http", Name: "a", Addr: "3000", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Fatal(err)
	}
	if err := h.d.RemoveTunnel(selfPeer(h), "a"); err != nil {
		t.Fatalf("daemon user: %v", err)
	}

	// A tunnel without an owner (added by the daemon user, or opened by the server) is not for unprivileged users.
	if _, err := h.d.AddTunnel(peer(0), localapi.AddTunnelRequest{Type: "http", Name: "r", Addr: "3001", Lifetime: localapi.LifetimeRuntime}); err != nil {
		t.Fatal(err)
	}
	_ = apiErr(t, h.d.RemoveTunnel(peer(bob), "r"), localapi.CodeForbidden)
	// An unknown name is still not_found, not forbidden.
	_ = apiErr(t, h.d.RemoveTunnel(peer(bob), "nope"), localapi.CodeNotFound)
}

func TestLocalAPIReloadNeedsPrivilege(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\n")
	user := otherUID()
	_, err := h.d.Reload(peer(user))
	_ = apiErr(t, err, localapi.CodeForbidden)
	if _, err := h.d.Reload(peer(0)); err != nil {
		t.Fatalf("root: %v", err)
	}
	if _, err := h.d.Reload(context.Background()); err != nil {
		t.Fatalf("no credentials: %v", err)
	}
}
