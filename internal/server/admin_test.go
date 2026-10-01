// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

func TestAdminBackendRegistry(t *testing.T) {
	h := newHarness(t)
	be := adminBackend{h.srv}
	ctx := context.Background()

	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "web", 0)
	c.mustRegister(proto.KindTCP, "db", 0)

	st, err := be.Status(ctx)
	if err != nil || st.Version != "test" || st.Clients != 1 || st.Tunnels != 2 || st.StartedAt.IsZero() {
		t.Fatalf("status %+v, %v", st, err)
	}
	h.clock.advance(90 * time.Second)
	if st, _ := be.Status(ctx); st.UptimeSeconds != 90 {
		t.Errorf("uptime %d, want 90", st.UptimeSeconds)
	}

	clients, _ := be.Clients(ctx)
	if len(clients) != 1 || clients[0].Name != "home" || clients[0].Tunnels != 2 || clients[0].SessionID != c.ok.SessionID || clients[0].Remote == "" {
		t.Fatalf("clients %+v", clients)
	}
	tunnels, _ := be.Tunnels(ctx)
	if len(tunnels) != 2 || tunnels[0].Name != "db" || tunnels[0].Kind != proto.KindTCP || tunnels[0].Port == 0 ||
		tunnels[1].Name != "web" || tunnels[1].ID != reg.TunnelID || tunnels[1].Client != "home" || tunnels[1].URL != reg.PublicURL {
		t.Fatalf("tunnels %+v", tunnels)
	}
}

func TestAdminBackendCloseTunnel(t *testing.T) {
	h := newHarness(t)
	be := adminBackend{h.srv}
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "web", 0)

	if err := be.CloseTunnel(context.Background(), "nope"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("unknown tunnel: %v", err)
	}
	if err := be.CloseTunnel(context.Background(), reg.TunnelID); err != nil {
		t.Fatal(err)
	}
	if m, ok := c.next().(*proto.TunnelClosed); !ok || m.TunnelID != reg.TunnelID {
		t.Fatalf("client was not told: %+v", m)
	}
	if n := h.srv.tunnelCount(); n != 0 {
		t.Errorf("%d tunnels left in the registry", n)
	}
	if err := be.CloseTunnel(context.Background(), reg.TunnelID); !errors.Is(err, adminapi.ErrNotFound) {
		t.Errorf("second close: %v", err)
	}
	// The session survives and can register again under the same name.
	c.mustRegister(proto.KindHTTP, "web", 0)
}

func TestAdminBackendDisconnect(t *testing.T) {
	h := newHarness(t)
	be := adminBackend{h.srv}
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)

	if err := be.Disconnect(context.Background(), "ghost"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("offline client: %v", err)
	}
	if err := be.Disconnect(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	c.waitClosed()
	waitFor(t, "session removal", func() bool { return h.srv.sessionCount() == 0 && h.srv.tunnelCount() == 0 })
}

// adminDo calls the admin API on the control host of the harness with a bearer token.
func adminDo(t *testing.T, h *harness, method, path, bearer string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, h.web.URL+adminapi.Prefix+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = testDomain
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := h.httpc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAdminBearerEndpoint(t *testing.T) {
	h := newHarness(t)
	admin := h.st.newToken(t, "agent", func(tok *store.Token) { tok.Scopes = []string{auth.ScopeAdminRead, auth.ScopeAdminClients} })
	plain := h.st.newToken(t, "plain")
	c := h.login(h.st.newToken(t, "home"))
	c.mustRegister(proto.KindHTTP, "web", 0)

	if status, _ := adminDo(t, h, "GET", "/status", ""); status != http.StatusUnauthorized {
		t.Errorf("no token: %d", status)
	}
	if status, _ := adminDo(t, h, "GET", "/status", "ph_bad_token"); status != http.StatusUnauthorized {
		t.Errorf("bad token: %d", status)
	}
	// A client token without admin scopes authenticates but may do nothing.
	if status, body := adminDo(t, h, "GET", "/status", plain.str); status != http.StatusForbidden {
		t.Errorf("client token: %d %s", status, body)
	}
	status, body := adminDo(t, h, "GET", "/clients", admin.str)
	var out struct {
		Clients []adminapi.Client `json:"clients"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || len(out.Clients) != 1 || out.Clients[0].Name != "home" {
		t.Fatalf("clients: %d %s", status, body)
	}
	if status, body := adminDo(t, h, "DELETE", "/tunnels/x", admin.str); status != http.StatusForbidden {
		t.Errorf("close tunnel without admin:tunnels: %d %s", status, body)
	}
	if status, body := adminDo(t, h, "POST", "/clients/home/disconnect", admin.str); status != http.StatusOK {
		t.Fatalf("disconnect: %d %s", status, body)
	}
	c.waitClosed()

	entries, _ := h.st.ListAudit(context.Background(), 10)
	if len(entries) != 2 || entries[0].Action != "client.disconnect" || entries[0].Result != "ok" || entries[0].Actor != admin.id ||
		entries[1].Action != "tunnel.close" || entries[1].Result != "denied" {
		t.Errorf("audit %+v", entries)
	}
	if strings.Contains(entries[0].Args, admin.str) {
		t.Error("the token leaked into the audit args")
	}
}

func TestAdminBearerRevokedAndLimited(t *testing.T) {
	h := newHarness(t)
	admin := h.st.newToken(t, "agent", func(tok *store.Token) { tok.Scopes = []string{auth.ScopeAdminRead} })
	h.st.update(admin.id, func(tok *store.Token) { now := h.clock.Now(); tok.RevokedAt = &now })
	if status, _ := adminDo(t, h, "GET", "/status", admin.str); status != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", status)
	}
	// Failures count against the same per-IP limiter as handshakes; the budget is failBurst.
	var last int
	for range failBurst + 2 {
		last, _ = adminDo(t, h, "GET", "/status", "ph_bad_token")
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("after many failures: %d, want 429", last)
	}
}

func TestAdminBearerOnlyOnControlHost(t *testing.T) {
	h := newHarness(t)
	admin := h.st.newToken(t, "agent", func(tok *store.Token) { tok.Scopes = []string{auth.ScopeAdminRead} })
	// On a tunnel's host the path belongs to the tunnelled application, not to the admin API.
	req, _ := http.NewRequest(http.MethodGet, h.web.URL+adminapi.Prefix+"/status", nil)
	req.Host = "web-home." + testDomain
	req.Header.Set("Authorization", "Bearer "+admin.str)
	resp, err := h.httpc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("admin API answered on a tunnel host")
	}
}
