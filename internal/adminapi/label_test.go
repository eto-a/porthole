// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"testing"

	"github.com/eto-a/porthole/internal/auth"
)

func TestReleaseLabel(t *testing.T) {
	e := newEnv(t, map[string][]string{
		"tu": {auth.ScopeAdminTunnels},
		"tk": {auth.ScopeAdminTokens},
	})
	e.st.labels = map[string]bool{"web-a-home": true}
	h := e.api.BearerHandler()

	if status, body, _ := e.do(h, "POST", "/labels/web-a-home/release", "ph_tk_secret"); status != 403 {
		t.Errorf("release without admin:tunnels: %d %s", status, body)
	}
	if !e.st.labels["web-a-home"] {
		t.Fatal("a denied call released the label")
	}
	if status, body, _ := e.do(h, "POST", "/labels/web-a-home/release", "ph_tu_secret"); status != 200 {
		t.Errorf("release: %d %s", status, body)
	}
	if e.st.labels["web-a-home"] {
		t.Error("the label is still claimed")
	}
	if status, body, _ := e.do(h, "POST", "/labels/web-a-home/release", "ph_tu_secret"); status != 404 {
		t.Errorf("release of a free label: %d %s", status, body)
	}

	want := []struct{ action, target, result string }{
		{"label.release", "web-a-home", "denied"},
		{"label.release", "web-a-home", "ok"},
		{"label.release", "web-a-home", "error: not_found"},
	}
	if len(e.st.audit) != len(want) {
		t.Fatalf("audit %+v", e.st.audit)
	}
	for i, w := range want {
		if a := e.st.audit[i]; a.Action != w.action || a.Target != w.target || a.Result != w.result {
			t.Errorf("audit[%d] = %+v, want %+v", i, a, w)
		}
	}
}
