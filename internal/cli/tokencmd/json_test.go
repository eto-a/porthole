// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package tokencmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
)

func TestCreateAndRevokeJSON(t *testing.T) {
	h := newHarness(t)
	out := h.mustRun("create", "--name", "home", "--expires", "30d", "--json")
	var created struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		Token     string     `json:"token"`
		Login     string     `json:"login"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("create --json is not one JSON document: %v\n%s", err, out)
	}
	tok, err := auth.Parse(created.Token)
	if err != nil || tok.ID != created.ID || created.Name != "home" || created.ExpiresAt == nil || len(created.Scopes) == 0 {
		t.Errorf("created: %+v (parse error %v)", created, err)
	}
	if want := "porthole login https://tun.example.com " + created.Token; created.Login != want {
		t.Errorf("login = %q, want %q", created.Login, want)
	}
	// The secret appears only in the create document.
	if list := h.mustRun("list", "--json"); strings.Contains(list, created.Token) {
		t.Errorf("list --json leaks the token:\n%s", list)
	}

	var revoked struct {
		ID             string `json:"id"`
		Revoked        bool   `json:"revoked"`
		AlreadyRevoked bool   `json:"already_revoked"`
	}
	for i, ref := range []string{"home", created.ID} {
		out = h.mustRun("revoke", ref, "--json")
		if err := json.Unmarshal([]byte(out), &revoked); err != nil {
			t.Fatalf("revoke --json: %v\n%s", err, out)
		}
		if revoked.ID != created.ID || !revoked.Revoked || revoked.AlreadyRevoked != (i == 1) {
			t.Errorf("revoke #%d: %+v", i, revoked)
		}
	}
}
