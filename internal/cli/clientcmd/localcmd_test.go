// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/localapi"
)

func sampleTunnels() []localapi.Tunnel {
	return []localapi.Tunnel{
		{
			Name: "blog", Type: "http", LocalAddr: "127.0.0.1:3000", PublicURL: "https://blog-home.tun.example.com",
			State: localapi.TunnelReady, Source: localapi.SourceFile, Lifetime: localapi.LifetimeFile,
		},
		{
			Name: "db", Type: "tcp", LocalAddr: "nas.local:5432", State: localapi.TunnelFailed, Error: "port_unavailable: port 20017 is taken",
			Source: localapi.SourceRuntime, Lifetime: localapi.LifetimeRuntime,
		},
	}
}

func daemonWith(f *fakeAPI) deps {
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	return d
}

func TestStatusCommand(t *testing.T) {
	f := newFakeAPI()
	f.tunnels = sampleTunnels()
	stdout, _, err := execute(t, daemonWith(f), "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"pid 4242", "up 1m", "porthole 9.9", "/s/user",
		"https://tun.example.com, connected as home",
		"/etc/porthole/tunnels.yaml",
		"NAME", "blog", "https://blog-home.tun.example.com", "ready", "file",
		"db", "failed", "runtime",
		"db: port_unavailable: port 20017 is taken",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("status output does not contain %q:\n%s", want, stdout)
		}
	}
}

func TestStatusCommandBackoff(t *testing.T) {
	f := newFakeAPI()
	retry := time.Now().Add(5 * time.Second)
	f.status.State, f.status.RetryAt, f.status.LastError = localapi.StateBackoff, &retry, "dial tcp: refused"
	stdout, _, err := execute(t, daemonWith(f), "status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "not connected, retrying in") || !strings.Contains(stdout, "dial tcp: refused") ||
		!strings.Contains(stdout, "no tunnels") {
		t.Errorf("status output:\n%s", stdout)
	}
}

func TestStatusJSON(t *testing.T) {
	f := newFakeAPI()
	f.tunnels = sampleTunnels()
	stdout, _, err := execute(t, daemonWith(f), "status", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var st localapi.Status
	if err := json.Unmarshal([]byte(stdout), &st); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if st.PID != 4242 || len(st.Tunnels) != 2 || st.Tunnels[0].Name != "blog" || st.Tunnels[0].State != localapi.TunnelReady {
		t.Errorf("status %+v", st)
	}

	f.tunnels = nil
	stdout, _, err = execute(t, daemonWith(f), "status", "--json")
	if err != nil || !strings.Contains(stdout, `"tunnels": []`) {
		t.Errorf("an empty tunnel list must be [] and not null: %v\n%s", err, stdout)
	}
}

func TestTunnelsCommand(t *testing.T) {
	f := newFakeAPI()
	f.tunnels = sampleTunnels()
	for _, name := range []string{"tunnels", "ls"} {
		stdout, _, err := execute(t, daemonWith(f), name)
		if err != nil || !strings.Contains(stdout, "NAME") || !strings.Contains(stdout, "nas.local:5432") ||
			!strings.Contains(stdout, "LIFETIME") {
			t.Errorf("%s: err = %v, output:\n%s", name, err, stdout)
		}
	}
	stdout, _, err := execute(t, daemonWith(f), "tunnels", "--json")
	var ts []localapi.Tunnel
	if err != nil || json.Unmarshal([]byte(stdout), &ts) != nil || len(ts) != 2 {
		t.Errorf("--json: err = %v\n%s", err, stdout)
	}
	f.tunnels = nil
	if stdout, _, err := execute(t, daemonWith(f), "tunnels"); err != nil || !strings.Contains(stdout, "no tunnels") {
		t.Errorf("empty: err = %v\n%s", err, stdout)
	}
	if stdout, _, err := execute(t, daemonWith(f), "tunnels", "--json"); err != nil || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("empty --json: err = %v\n%s", err, stdout)
	}
}

func TestReloadCommand(t *testing.T) {
	f := newFakeAPI()
	f.reloadRes = localapi.ReloadResult{Added: []string{"web"}, Removed: []string{"db"}, Changed: []string{}, Unchanged: []string{"blog", "x"}}
	stdout, _, err := execute(t, daemonWith(f), "reload")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1 added, 1 removed, 0 changed, 2 unchanged", "added: web", "removed: db"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("reload output does not contain %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "changed:") {
		t.Errorf("empty groups must not be listed:\n%s", stdout)
	}

	f.reloadErr = localapi.NewError(localapi.CodeInvalidRequest, "tunnels file /x: tunnel %q: unknown type (keeping the current tunnels)", "a")
	_, _, err = execute(t, daemonWith(f), "reload")
	if err == nil || !strings.Contains(err.Error(), "unknown type") || !strings.Contains(err.Error(), "keeping the current tunnels") {
		t.Errorf("err = %v", err)
	}
	var e *localapi.Error
	if !errors.As(err, &e) {
		t.Error("the API error is not reachable")
	}

	f.reloadErr = nil
	f.reloadRes = localapi.ReloadResult{Errors: map[string]string{"b": "bad", "a": "worse"}}
	_, stderr, err := execute(t, daemonWith(f), "reload")
	if err == nil || strings.Index(stderr, "tunnel a: worse") > strings.Index(stderr, "tunnel b: bad") {
		t.Errorf("per-tunnel failures: err = %v, stderr %q", err, stderr)
	}
}

func TestCloseCommand(t *testing.T) {
	f := newFakeAPI()
	stdout, _, err := execute(t, daemonWith(f), "close", "tmp")
	if err != nil || !strings.Contains(stdout, "closed tmp") || !equalStrings(f.removed, []string{"tmp"}) {
		t.Fatalf("err = %v, stdout %q, removed %v", err, stdout, f.removed)
	}
	f.removeErr = localapi.NewError(localapi.CodeConflict, "tunnel %q is defined in tunnels.yaml; edit it and run `porthole reload`", "blog")
	_, _, err = execute(t, daemonWith(f), "close", "blog")
	if err == nil || err.Error() != "tunnel \"blog\" is defined in tunnels.yaml; edit it and run `porthole reload`" {
		t.Errorf("err = %v", err)
	}
	f.removeErr = localapi.NewError(localapi.CodeNotFound, "no tunnel named %q", "nope")
	if _, _, err := execute(t, daemonWith(f), "close", "nope"); err == nil || !strings.Contains(err.Error(), "no tunnel named") {
		t.Errorf("err = %v", err)
	}
	if _, _, err := execute(t, daemonWith(f), "close"); err == nil {
		t.Error("close without a name must fail")
	}
}

func TestLocalCommandsNeedADaemon(t *testing.T) {
	d, _ := withSockets(testDeps(nil), nil, "/s/user", "/s/system")
	for _, args := range [][]string{{"status"}, {"tunnels"}, {"reload"}, {"close", "x"}} {
		_, _, err := execute(t, d, args...)
		if err == nil || !strings.Contains(err.Error(), "no porthole daemon is running") ||
			!strings.Contains(err.Error(), "/s/user") || !strings.Contains(err.Error(), "/s/system") {
			t.Errorf("%v: err = %v", args, err)
		}
	}

	denied := newFakeAPI()
	denied.statusErr = errPerm
	d, _ = withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": denied}, "/s/user")
	_, _, err := execute(t, d, "status")
	if err == nil || !strings.Contains(err.Error(), accessAdvice(runtime.GOOS)) || strings.Contains(err.Error(), "--no-daemon") {
		t.Errorf("denied: err = %v (the hint must not offer --no-daemon: these commands need the daemon)", err)
	}
}

func TestLocalCommandsHonourTheSocketFlag(t *testing.T) {
	f := newFakeAPI()
	d, dialled := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/flag": f}, "/s/user")
	if _, _, err := execute(t, d, "--socket", "/s/flag", "status"); err != nil || !equalStrings(*dialled, []string{"/s/flag"}) {
		t.Errorf("err = %v, dialled %v", err, *dialled)
	}
}
