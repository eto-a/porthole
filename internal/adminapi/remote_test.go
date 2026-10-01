// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
)

func (f *fakeBackend) RequestTunnel(_ context.Context, client string, req RemoteOpen) (RemoteTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case client != "home":
		return RemoteTunnel{}, ErrNotFound
	case req.LocalAddr == "9":
		return RemoteTunnel{}, &RemoteError{Code: proto.CodeNotAllowed, Message: "no"}
	case req.LocalAddr == "8":
		return RemoteTunnel{}, &RemoteError{Code: proto.CodeTimeout, Message: "slow"}
	}
	f.opened = append(f.opened, req)
	return RemoteTunnel{Name: "http-" + req.LocalAddr, Kind: req.Kind, URL: "https://x.example.com"}, nil
}

func TestRemoteOpen(t *testing.T) {
	e := newEnv(t, map[string][]string{
		"r1": {auth.ScopeAdminRemote},
		"c1": {auth.ScopeAdminClients, auth.ScopeAdminRead},
	})
	h := e.api.BearerHandler()

	status, body := e.post(h, "/clients/home/tunnels", "ph_r1_secret", `{"kind":"http","local_addr":"3000","name":"web"}`)
	if status != http.StatusOK {
		t.Fatalf("open: %d %s", status, body)
	}
	var out struct {
		OK     bool         `json:"ok"`
		Tunnel RemoteTunnel `json:"tunnel"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || !out.OK || out.Tunnel.URL != "https://x.example.com" || out.Tunnel.Name != "http-3000" {
		t.Errorf("response %s (%v)", body, err)
	}
	if len(e.be.opened) != 1 || e.be.opened[0].Name != "web" || e.be.opened[0].RequestedBy != "r1" {
		t.Errorf("backend got %+v", e.be.opened)
	}

	if status, body = e.post(h, "/clients/home/tunnels", "ph_c1_secret", `{"kind":"http","local_addr":"3000"}`); status != http.StatusForbidden || errCode(t, body) != "forbidden" {
		t.Errorf("without scope: %d %s", status, body)
	}
	if status, body = e.post(h, "/clients/home/tunnels", "", `{}`); status != http.StatusUnauthorized {
		t.Errorf("anonymous: %d %s", status, body)
	}
	if status, body = e.post(h, "/clients/nobody/tunnels", "ph_r1_secret", `{"kind":"http","local_addr":"1"}`); status != http.StatusNotFound || errCode(t, body) != "not_found" {
		t.Errorf("offline client: %d %s", status, body)
	}
	if status, body = e.post(h, "/clients/home/tunnels", "ph_r1_secret", `{"kind":"http","local_addr":"9"}`); status != http.StatusForbidden || errCode(t, body) != proto.CodeNotAllowed {
		t.Errorf("not allowed: %d %s", status, body)
	}
	if status, body = e.post(h, "/clients/home/tunnels", "ph_r1_secret", `{"kind":"http","local_addr":"8"}`); status != http.StatusGatewayTimeout || errCode(t, body) != proto.CodeTimeout {
		t.Errorf("timeout: %d %s", status, body)
	}
	if status, body = e.post(h, "/clients/home/tunnels", "ph_r1_secret", `{"kind":"http","bogus":1}`); status != http.StatusBadRequest {
		t.Errorf("unknown field: %d %s", status, body)
	}

	// Every attempt by an authenticated caller is audited, with the acting token and without secrets.
	var results []string
	for _, a := range e.st.audit {
		if a.Action != ActionRemoteOpen {
			t.Errorf("unexpected action %q", a.Action)
		}
		if strings.Contains(a.Args, "secret") || strings.Contains(a.Args, "ph_") {
			t.Errorf("audit args hold a secret: %s", a.Args)
		}
		results = append(results, a.Target+":"+a.Result)
	}
	want := "home:ok home:denied nobody:error: not_found home:error: not_allowed home:error: timeout home:error: invalid_request"
	if got := strings.Join(results, " "); got != want {
		t.Errorf("audit results\n got %s\nwant %s", got, want)
	}
	if e.st.audit[0].Actor == "" || !strings.Contains(e.st.audit[0].Args, `"local_addr":"3000"`) {
		t.Errorf("audit entry %+v", e.st.audit[0])
	}
}
