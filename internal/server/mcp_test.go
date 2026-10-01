// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/eto-a/porthole/internal/auth"
	mcpserver "github.com/eto-a/porthole/internal/mcp/server"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

// mcpRoundTripper sends requests to the control host with a bearer token.
type mcpRoundTripper struct {
	base   http.RoundTripper
	host   string
	secret string
}

func (m mcpRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = m.host
	if m.secret != "" {
		r.Header.Set("Authorization", "Bearer "+m.secret)
	}
	return m.base.RoundTrip(r)
}

func TestMCPEndpoint(t *testing.T) {
	h := newHarness(t)
	admin := h.st.newToken(t, "agent", func(tok *store.Token) {
		tok.Scopes = []string{auth.ScopeAdminRead, auth.ScopeAdminTunnels}
	})
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "web", 0)

	// No token: 401, like the admin API.
	req, _ := http.NewRequest(http.MethodPost, h.web.URL+mcpserver.Path, strings.NewReader("{}"))
	req.Host = testDomain
	resp, err := h.httpc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ct := &mcp.StreamableClientTransport{
		Endpoint:             h.web.URL + mcpserver.Path,
		HTTPClient:           &http.Client{Transport: mcpRoundTripper{base: h.httpc.Transport, host: testDomain, secret: admin.str}},
		DisableStandaloneSSE: true,
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_tunnels", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("list_tunnels: %v %+v", err, res)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "close_tunnel", Arguments: map[string]any{"id": reg.TunnelID}})
	if err != nil || res.IsError {
		t.Fatalf("close_tunnel: %v %+v", err, res)
	}
	if m, ok := c.next().(*proto.TunnelClosed); !ok || m.TunnelID != reg.TunnelID {
		t.Fatalf("client was not told: %+v", m)
	}

	entries, _ := h.st.ListAudit(context.Background(), 10)
	if len(entries) != 1 || entries[0].Action != "mcp.close_tunnel" || entries[0].Actor != admin.id ||
		entries[0].Target != reg.TunnelID || entries[0].Result != "ok" {
		t.Errorf("audit %+v", entries)
	}
	if strings.Contains(entries[0].Args, admin.str) {
		t.Error("the token leaked into the audit args")
	}
}
