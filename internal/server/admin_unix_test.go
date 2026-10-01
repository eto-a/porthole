// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/proto"
)

func TestAdminSocket(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := adminapi.ListenUnix(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.StartAdminSocket(ln); err != nil {
		t.Fatal(err)
	}
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := adminapi.NewSocketClient(path).Status(ctx)
	if err != nil || st.Clients != 1 || st.Tunnels != 1 || st.Version != "test" {
		t.Fatalf("status %+v, %v", st, err)
	}
}
