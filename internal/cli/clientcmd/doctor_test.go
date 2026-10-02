// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/service"
)

// doctorTest is a set of deps with a good config file, a fake server check, no daemon and no service.
type doctorTest struct {
	d     deps
	cfg   string
	token string
	api   *fakeAPI
	mgr   *fakeManager
}

func newDoctorTest(t *testing.T) *doctorTest {
	t.Helper()
	tok := testToken(t)
	dt := &doctorTest{token: tok, api: newFakeAPI(), mgr: &fakeManager{}}
	dt.cfg = writeConfig(t, "https://tun.example.com", tok)
	dt.d = testDeps(nil)
	dt.d.lookup = func(context.Context, string) ([]string, error) { return []string{"203.0.113.7"}, nil }
	dt.d.socketPaths = func() []string { return []string{filepath.Join(t.TempDir(), "none.sock")} }
	dt.api.statusErr = fmt.Errorf("localapi: GET /v1/status: %w", os.ErrNotExist)
	dt.d.dial = func(string) apiClient { return dt.api }
	dt.d.newService = func(bool) (service.Manager, error) { return dt.mgr, nil }
	return dt
}

func (dt *doctorTest) run(t *testing.T, args ...string) (doctorReport, string, error) {
	t.Helper()
	out, _, err := execute(t, dt.d, append([]string{"--config", dt.cfg, "doctor"}, args...)...)
	var rep doctorReport
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		if jerr := json.Unmarshal([]byte(out), &rep); jerr != nil {
			t.Fatalf("bad JSON %q: %v", out, jerr)
		}
	}
	return rep, out, err
}

func findCheck(t *testing.T, rep doctorReport, name string) doctorCheck {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", name, rep.Checks)
	return doctorCheck{}
}

func TestDoctorAllOK(t *testing.T) {
	dt := newDoctorTest(t)
	out, _, err := execute(t, dt.d, "--config", dt.cfg, "doctor")
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	for _, want := range []string{"config", "dns", "server", "daemon", "tunnels_file", "service", "logged in as", "no daemon", "not installed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, dt.token) {
		t.Errorf("the token is printed:\n%s", out)
	}
	if strings.Contains(out, "fail") {
		t.Errorf("unexpected failure:\n%s", out)
	}
}

func TestDoctorMissingConfig(t *testing.T) {
	dt := newDoctorTest(t)
	dt.cfg = filepath.Join(t.TempDir(), "absent.yaml")
	rep, out, err := dt.run(t, "--json")
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v (exit %d), want exit 1", err, ExitCode(err))
	}
	if rep.OK {
		t.Errorf("ok = true for a missing config:\n%s", out)
	}
	c := findCheck(t, rep, "config")
	if c.Status != doctorFail || !strings.Contains(c.Hint, "porthole join") || !strings.Contains(c.Hint, "porthole login") {
		t.Errorf("config check = %+v", c)
	}
	for _, c := range rep.Checks {
		if c.Name == "dns" || c.Name == "server" {
			t.Errorf("check %q ran without a config", c.Name)
		}
	}
}

func TestDoctorConfigWithoutToken(t *testing.T) {
	dt := newDoctorTest(t)
	if err := saveConfig(dt.cfg, fileConfig{Server: "https://tun.example.com"}); err != nil {
		t.Fatal(err)
	}
	rep, _, err := dt.run(t, "--json")
	if err == nil || findCheck(t, rep, "config").Status != doctorFail {
		t.Errorf("err = %v, config = %+v", err, findCheck(t, rep, "config"))
	}
}

func TestDoctorAuthError(t *testing.T) {
	dt := newDoctorTest(t)
	dt.d.check = func(context.Context, client.Options) (client.CheckResult, error) {
		return client.CheckResult{}, fmt.Errorf("handshake: %w", &proto.Error{Code: proto.CodeTokenRevoked, Message: "revoked"})
	}
	rep, _, err := dt.run(t, "--json")
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v, want exit 1", err)
	}
	c := findCheck(t, rep, "server")
	if c.Status != doctorFail || !strings.Contains(c.Hint, "porthole join") {
		t.Errorf("server check = %+v", c)
	}
}

func TestDoctorNetworkError(t *testing.T) {
	dt := newDoctorTest(t)
	dt.d.check = func(context.Context, client.Options) (client.CheckResult, error) {
		return client.CheckResult{}, errors.New("dial tcp: connection refused")
	}
	rep, _, err := dt.run(t, "--json")
	c := findCheck(t, rep, "server")
	if err == nil || c.Status != doctorFail || !strings.Contains(c.Message, "connection refused") {
		t.Errorf("err = %v, server check = %+v", err, c)
	}
}

func TestDoctorDNSFailure(t *testing.T) {
	dt := newDoctorTest(t)
	dt.d.lookup = func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") }
	rep, _, err := dt.run(t, "--json")
	if err == nil || findCheck(t, rep, "dns").Status != doctorFail || findCheck(t, rep, "server").Status != doctorWarn {
		t.Errorf("err = %v, checks = %+v", err, rep.Checks)
	}
}

func TestDoctorDaemon(t *testing.T) {
	dt := newDoctorTest(t)
	dt.api.statusErr = nil
	dt.api.status.Version = "1.2.3"
	rep, _, err := dt.run(t, "--json")
	if err != nil {
		t.Fatal(err)
	}
	if c := findCheck(t, rep, "daemon"); c.Status != doctorOK || !strings.Contains(c.Message, "version 1.2.3") {
		t.Errorf("daemon check = %+v", c)
	}

	dt.api.status.Version = "0.0.1" // the test CLI is 1.2.3
	rep, _, err = dt.run(t, "--json")
	if err != nil {
		t.Fatalf("a version skew is a warning: %v", err)
	}
	if c := findCheck(t, rep, "daemon"); c.Status != doctorWarn || c.Hint == "" {
		t.Errorf("skew: daemon check = %+v", c)
	}

	dt.api.statusErr = fmt.Errorf("localapi: GET /v1/status: %w", os.ErrPermission)
	rep, _, err = dt.run(t, "--json")
	if err != nil {
		t.Fatalf("permission denied is a warning: %v", err)
	}
	if c := findCheck(t, rep, "daemon"); c.Status != doctorWarn || !strings.Contains(c.Message, "permission denied") {
		t.Errorf("denied: daemon check = %+v", c)
	}
}

func TestDoctorTunnelsFile(t *testing.T) {
	dt := newDoctorTest(t)
	path := filepath.Join(filepath.Dir(dt.cfg), tunnelsFileName)
	if err := os.WriteFile(path, []byte("version: 1\ntunnels:\n  web:\n    type: http\n    addr: \"3000\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _, err := dt.run(t, "--json")
	if c := findCheck(t, rep, "tunnels_file"); err != nil || c.Status != doctorOK || !strings.Contains(c.Message, "1 tunnel") {
		t.Errorf("err = %v, tunnels_file = %+v", err, c)
	}
	if err := os.WriteFile(path, []byte("version: 1\ntunnels:\n  web:\n    type: bogus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _, err = dt.run(t, "--json")
	if c := findCheck(t, rep, "tunnels_file"); err == nil || c.Status != doctorFail || c.Message == "" {
		t.Errorf("err = %v, tunnels_file = %+v", err, c)
	}
}

func TestDoctorService(t *testing.T) {
	dt := newDoctorTest(t)
	dt.mgr.state = service.State{Installed: true, Running: true, PID: 42}
	rep, _, err := dt.run(t, "--json")
	if c := findCheck(t, rep, "service"); err != nil || c.Status != doctorOK || !strings.Contains(c.Message, "running (pid 42)") {
		t.Errorf("err = %v, service = %+v", err, c)
	}
	dt.mgr.state = service.State{Installed: true, Detail: "inactive"}
	rep, _, err = dt.run(t, "--json")
	if c := findCheck(t, rep, "service"); err != nil || c.Status != doctorWarn || c.Hint == "" {
		t.Errorf("err = %v, service = %+v", err, c)
	}
	dt.d.newService = func(bool) (service.Manager, error) { return nil, service.ErrUnsupported }
	rep, _, err = dt.run(t, "--json")
	if c := findCheck(t, rep, "service"); err != nil || c.Status != doctorOK {
		t.Errorf("err = %v, service = %+v", err, c)
	}
}

func TestDoctorJSONShape(t *testing.T) {
	dt := newDoctorTest(t)
	_, out, err := dt.run(t, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["ok"] != true {
		t.Errorf("ok = %v", raw["ok"])
	}
	checks, _ := raw["checks"].([]any)
	if len(checks) != 6 {
		t.Fatalf("%d checks, want 6: %s", len(checks), out)
	}
	for _, c := range checks {
		m, _ := c.(map[string]any)
		for _, k := range []string{"name", "status", "message", "hint"} {
			if _, ok := m[k]; !ok {
				t.Errorf("check %v lacks %q", m, k)
			}
		}
	}
}

func TestDoctorSystemAndConfigConflict(t *testing.T) {
	dt := newDoctorTest(t)
	_, _, err := dt.run(t, "--system")
	if err == nil || ExitCode(err) == 0 {
		t.Errorf("--system with --config: err = %v", err)
	}
}
