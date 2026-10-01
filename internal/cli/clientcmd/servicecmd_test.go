// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/daemon"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/service"
)

// fakeManager records what the commands ask of the service manager.
type fakeManager struct {
	calls      []string
	specs      []service.Spec
	state      service.State
	installErr error
	opErr      error // returned by Uninstall, Start, Stop and Restart
}

func (f *fakeManager) Install(s service.Spec) error {
	f.calls = append(f.calls, "install")
	f.specs = append(f.specs, s)
	if f.installErr == nil {
		f.state = service.State{Installed: true, Running: true, PID: 42, Detail: "active"}
	}
	return f.installErr
}

func (f *fakeManager) op(name string) error {
	f.calls = append(f.calls, name)
	return f.opErr
}
func (f *fakeManager) Uninstall(string) error { return f.op("uninstall") }
func (f *fakeManager) Start(string) error     { return f.op("start") }
func (f *fakeManager) Stop(string) error      { return f.op("stop") }
func (f *fakeManager) Restart(string) error   { return f.op("restart") }
func (f *fakeManager) Status(string) (service.State, error) {
	return f.state, nil
}

// svcTest is a set of deps for the service commands: a fake manager, a system directory under a temp directory and
// a user config directory that is empty.
type svcTest struct {
	d       deps
	m       *fakeManager
	sysDir  string
	userDir string
	users   []bool // the user argument of every newService call
}

func newSvcTest(t *testing.T) *svcTest {
	t.Helper()
	s := &svcTest{m: &fakeManager{}, sysDir: filepath.Join(t.TempDir(), "sys"), userDir: t.TempDir()}
	s.d = testDeps(map[string]string{"ProgramData": filepath.Join(t.TempDir(), "pd")})
	s.d.userConfigDir = func() (string, error) { return s.userDir, nil }
	s.d.userSocket = func() string { return filepath.Join(s.userDir, "user.sock") }
	s.d.newService = func(user bool) (service.Manager, error) { s.users = append(s.users, user); return s.m, nil }
	s.d.prepareDir = func() (string, error) { return s.sysDir, os.MkdirAll(s.sysDir, 0o750) }
	s.d.executable = func() (string, error) { return filepath.Join(t.TempDir(), "bin", "porthole"), nil }
	return s
}

func (s *svcTest) sysConfig() string { return filepath.Join(s.sysDir, "config.yaml") }

const testServer = "https://tun.example.com"

func TestLoginSystemWritesTheSystemConfig(t *testing.T) {
	s := newSvcTest(t)
	tok := testToken(t)
	if _, _, err := execute(t, s.d, "login", "--system", testServer, tok); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(s.sysConfig())
	if err != nil || cfg.Server != testServer || cfg.Token != tok {
		t.Fatalf("system config = %+v, %v", cfg, err)
	}
	if _, err := os.Stat(filepath.Join(s.userDir, "porthole", "config.yaml")); err == nil {
		t.Error("login --system also wrote the user config")
	}
	if _, _, err := execute(t, s.d, "--config", "x.yaml", "login", "--system", testServer, tok); err == nil {
		t.Error("--system together with --config was accepted")
	}
}

func TestLoginSystemNeedsElevation(t *testing.T) {
	s := newSvcTest(t)
	s.d.prepareDir = func() (string, error) { return "", service.ErrNotElevated }
	_, _, err := execute(t, s.d, "login", "--system", testServer, testToken(t))
	if err == nil || !strings.Contains(err.Error(), elevationHint(runtime.GOOS, "login --system")) {
		t.Fatalf("err = %v, want the elevation hint", err)
	}
}

func TestServiceInstallSystem(t *testing.T) {
	s := newSvcTest(t)
	tok := testToken(t)
	if _, _, err := execute(t, s.d, "login", "--system", testServer, tok); err != nil {
		t.Fatal(err)
	}
	var fixed [2]string
	s.d.fixOwnership = func(cfg, tun string) (bool, error) { fixed = [2]string{cfg, tun}; return false, nil }

	out, _, err := execute(t, s.d, "service", "install", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.m.specs) != 1 {
		t.Fatalf("Install calls = %d, want 1", len(s.m.specs))
	}
	spec := s.m.specs[0]
	want := []string{
		"daemon", "--config", s.sysConfig(), "--tunnels", filepath.Join(s.sysDir, "tunnels.yaml"),
		"--socket", localapi.SystemSocketPath,
	}
	if spec.User || strings.Join(spec.Args, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("spec = %+v, want args %q", spec, want)
	}
	if fixed != [2]string{s.sysConfig(), filepath.Join(s.sysDir, "tunnels.yaml")} {
		t.Errorf("files handed to the service account = %q", fixed)
	}
	if _, err := os.Stat(filepath.Join(s.sysDir, "tunnels.yaml")); err != nil {
		t.Errorf("tunnels.yaml was not created: %v", err)
	}
	var res serviceResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if res.Action != "install" || res.Service == nil || !res.Service.Running || res.Socket != localapi.SystemSocketPath {
		t.Errorf("result = %+v", res)
	}
	if strings.Contains(out, tok) {
		t.Error("the token is in the output")
	}
}

func TestServiceInstallKeepsExistingFilesAndRefusesBrokenOnes(t *testing.T) {
	s := newSvcTest(t)
	if _, _, err := execute(t, s.d, "login", "--system", testServer, testToken(t)); err != nil {
		t.Fatal(err)
	}
	tunnels := filepath.Join(s.sysDir, "tunnels.yaml")
	mine := "version: 1\n# mine\ntunnels: {}\n"
	if err := os.WriteFile(tunnels, []byte(mine), 0o640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.sysConfig())
	if _, _, err := execute(t, s.d, "service", "install"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(tunnels); string(got) != mine {
		t.Errorf("tunnels.yaml was overwritten: %q", got)
	}
	if got, _ := os.ReadFile(s.sysConfig()); !bytes.Equal(got, before) {
		t.Error("config.yaml was overwritten")
	}

	if err := os.WriteFile(tunnels, []byte("{{{"), 0o640); err != nil {
		t.Fatal(err)
	}
	s.m.calls = nil
	_, _, err := execute(t, s.d, "service", "install")
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitConfig {
		t.Fatalf("err = %v, want a configuration error", err)
	}
	if len(s.m.calls) != 0 {
		t.Errorf("the service was touched despite a broken tunnels file: %v", s.m.calls)
	}
}

func TestServiceInstallNeedsCredentials(t *testing.T) {
	s := newSvcTest(t)
	_, _, err := execute(t, s.d, "service", "install")
	if err == nil || !strings.Contains(err.Error(), "porthole login --system") {
		t.Fatalf("err = %v, want advice to log in", err)
	}
	if len(s.m.calls) != 0 {
		t.Errorf("manager calls = %v", s.m.calls)
	}
}

func TestServiceInstallCopiesTheUserConfig(t *testing.T) {
	s := newSvcTest(t)
	tok := testToken(t)
	if err := saveConfig(filepath.Join(s.userDir, "porthole", "config.yaml"), fileConfig{Server: testServer, Token: tok}); err != nil {
		t.Fatal(err)
	}
	out, _, err := execute(t, s.d, "service", "install")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(s.sysConfig())
	if err != nil || cfg.Token != tok || cfg.Server != testServer {
		t.Fatalf("copied config = %+v, %v", cfg, err)
	}
	if !strings.Contains(out, "copied from your own config file") || strings.Contains(out, tok) {
		t.Errorf("output = %q", out)
	}
}

func TestServiceInstallNeedsElevation(t *testing.T) {
	s := newSvcTest(t)
	s.d.prepareDir = func() (string, error) { return "", service.ErrNotElevated }
	_, _, err := execute(t, s.d, "service", "install")
	if err == nil || !strings.Contains(err.Error(), elevationHint(runtime.GOOS, "service install")) {
		t.Fatalf("err = %v, want the elevation hint", err)
	}
	if len(s.m.calls) != 0 {
		t.Errorf("manager calls = %v", s.m.calls)
	}

	// The manager may be the one to refuse (Install, Uninstall, Start on Windows).
	s = newSvcTest(t)
	s.m.opErr = service.ErrNotElevated
	for _, verb := range []string{"uninstall", "start", "stop", "restart"} {
		_, _, err := execute(t, s.d, "service", verb)
		if err == nil || !strings.Contains(err.Error(), elevationHint(runtime.GOOS, "service "+verb)) {
			t.Errorf("%s: err = %v, want the elevation hint", verb, err)
		}
	}
}

func TestServiceInstallUser(t *testing.T) {
	s := newSvcTest(t)
	tok := testToken(t)
	if err := saveConfig(filepath.Join(s.userDir, "porthole", "config.yaml"), fileConfig{Server: testServer, Token: tok}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := execute(t, s.d, "service", "install", "--user"); err != nil {
		t.Fatal(err)
	}
	spec := s.m.specs[0]
	if !spec.User || s.users[len(s.users)-1] != true {
		t.Errorf("spec.User = %v, newService(user) = %v", spec.User, s.users)
	}
	cfg := filepath.Join(s.userDir, "porthole", "config.yaml")
	want := []string{
		"daemon", "--config", cfg, "--tunnels", filepath.Join(s.userDir, "porthole", "tunnels.yaml"),
		"--socket", filepath.Join(s.userDir, "user.sock"),
	}
	if strings.Join(spec.Args, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("args = %q, want %q", spec.Args, want)
	}
	if _, err := os.Stat(s.sysDir); err == nil {
		t.Error("--user touched the system directory")
	}
}

func TestServiceInstallExplicitPaths(t *testing.T) {
	s := newSvcTest(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yaml")
	if err := saveConfig(cfg, fileConfig{Server: testServer, Token: testToken(t)}); err != nil {
		t.Fatal(err)
	}
	tun := filepath.Join(dir, "t.yaml")
	if _, _, err := execute(t, s.d, "--config", cfg, "--socket", "/custom/p.sock", "service", "install", "--tunnels", tun); err != nil {
		t.Fatal(err)
	}
	want := []string{"daemon", "--config", cfg, "--tunnels", tun, "--socket", "/custom/p.sock"}
	if got := s.m.specs[0].Args; strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("args = %q, want %q", got, want)
	}
}

func TestServiceInstallAllow(t *testing.T) {
	s := newSvcTest(t)
	if _, _, err := execute(t, s.d, "login", "--system", testServer, testToken(t)); err != nil {
		t.Fatal(err)
	}
	_, _, err := execute(t, s.d, "service", "install", "--allow", `BUILTIN\Users`, "--allow", "devs")
	if runtime.GOOS != "windows" {
		if err == nil || len(s.m.calls) != 0 {
			t.Fatalf("--allow outside Windows: err = %v, calls = %v; want a usage error", err, s.m.calls)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(s.m.specs[0].Args, " ")
	if !strings.Contains(args, `--allow BUILTIN\Users --allow devs`) {
		t.Errorf("args = %q", args)
	}
}

func TestServiceInstallHandsFilesOverAndRestarts(t *testing.T) {
	s := newSvcTest(t)
	if _, _, err := execute(t, s.d, "login", "--system", testServer, testToken(t)); err != nil {
		t.Fatal(err)
	}
	// The first call (before Install) finds no account; the second (after it) changes the files.
	n := 0
	s.d.fixOwnership = func(string, string) (bool, error) { n++; return n == 2, nil }
	s.m.installErr = errors.New("the service failed to start")
	if _, _, err := execute(t, s.d, "service", "install"); err != nil {
		t.Fatalf("a restart that cures the failed start must make install succeed: %v", err)
	}
	if got := strings.Join(s.m.calls, ","); got != "install,restart" {
		t.Errorf("calls = %s, want install,restart", got)
	}

	s.m.calls, n = nil, 100 // nothing changes: the install error stands
	if _, _, err := execute(t, s.d, "service", "install"); err == nil {
		t.Error("a failed install without a cure was reported as success")
	}
}

func TestServiceWindowsUserIsExplained(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the hint is Windows-specific")
	}
	s := newSvcTest(t)
	s.d.newService = func(bool) (service.Manager, error) { return nil, fmt.Errorf("x: %w", service.ErrUnsupported) }
	_, _, err := execute(t, s.d, "service", "install", "--user")
	if err == nil || !strings.Contains(err.Error(), "Task Scheduler") {
		t.Fatalf("err = %v", err)
	}
}

func TestServiceVerbs(t *testing.T) {
	for _, verb := range []string{"uninstall", "start", "stop", "restart"} {
		s := newSvcTest(t)
		out, _, err := execute(t, s.d, "service", verb)
		if err != nil || len(s.m.calls) != 1 || s.m.calls[0] != verb {
			t.Errorf("%s: err = %v, calls = %v", verb, err, s.m.calls)
		}
		if !strings.Contains(out, "system service") {
			t.Errorf("%s: output = %q", verb, out)
		}
		_, _, _ = execute(t, s.d, "service", verb, "--user")
		if s.users[len(s.users)-1] != true {
			t.Errorf("%s --user did not select the user manager", verb)
		}
	}
	s := newSvcTest(t)
	s.m.opErr = service.ErrNotInstalled
	_, _, err := execute(t, s.d, "service", "start")
	if err == nil || !strings.Contains(err.Error(), "porthole service install") {
		t.Errorf("start of a missing service: err = %v", err)
	}
}

func TestServiceStatus(t *testing.T) {
	s := newSvcTest(t)
	s.m.state = service.State{Installed: true, Running: true, PID: 7, Detail: "active (running)"}
	api := newFakeAPI()
	api.status = localapi.Status{State: "connected", Server: testServer, ClientName: "home", Version: "1.2.3"}
	s.d, _ = withSockets(s.d, map[string]*fakeAPI{localapi.SystemSocketPath: api})
	dialled := ""
	inner := s.d.dial
	s.d.dial = func(p string) apiClient { dialled = p; return inner(p) }

	out, _, err := execute(t, s.d, "service", "status", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var res serviceResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if res.Service == nil || !res.Service.Running || res.Service.PID != 7 || res.API == nil || res.API.Status == nil ||
		res.API.Status.ClientName != "home" || dialled != localapi.SystemSocketPath {
		t.Errorf("result = %+v (dialled %q)", res, dialled)
	}

	text, _, err := execute(t, s.d, "service", "status")
	if err != nil || !strings.Contains(text, "running (pid 7)") || !strings.Contains(text, `connected to `+testServer+` as "home"`) {
		t.Errorf("text = %q, err = %v", text, err)
	}

	// Not installed: no API probe, exit status 0.
	s.m.state = service.State{}
	dialled = ""
	text, _, err = execute(t, s.d, "service", "status")
	if err != nil || !strings.Contains(text, "not installed") || dialled != "" {
		t.Errorf("not installed: text = %q, err = %v, dialled %q", text, err, dialled)
	}

	// Running but the daemon does not answer: reported, not an error.
	s.m.state = service.State{Installed: true, Running: true}
	s.d, _ = withSockets(s.d, nil)
	text, _, err = execute(t, s.d, "service", "status")
	if err != nil || !strings.Contains(text, "no answer") {
		t.Errorf("no answer: text = %q, err = %v", text, err)
	}
}

func TestServiceHelpers(t *testing.T) {
	if w := suspiciousExe(filepath.Join(os.TempDir(), "x", "porthole"), os.TempDir()); w == "" {
		t.Error("a binary in the temp directory was not flagged")
	}
	if w := suspiciousExe("/home/me/Downloads/porthole", os.TempDir()); w == "" {
		t.Error("a binary in Downloads was not flagged")
	}
	if w := suspiciousExe("/usr/local/bin/porthole", "/tmp"); w != "" {
		t.Errorf("a binary in /usr/local/bin was flagged: %s", w)
	}
	if h := elevationHint("windows", "service install"); !strings.Contains(h, "Administrator") {
		t.Errorf("windows hint = %q", h)
	}
	if h := elevationHint("linux", "service install"); !strings.Contains(h, "sudo porthole service install") {
		t.Errorf("linux hint = %q", h)
	}
}

// On macOS the system endpoint exists only while a system daemon runs; a user without it must fall through to
// "no daemon" (and so to running in-process), not fail.
func TestMissingSystemEndpointFallsThrough(t *testing.T) {
	enoent := &net.OpError{Op: "dial", Net: "unix", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ENOENT}}
	d := testDeps(nil)
	d.socketPaths = func() []string {
		return []string{"/Users/me/Library/Caches/porthole/porthole.sock", "/var/run/porthole/porthole.sock"}
	}
	d.dial = func(string) apiClient {
		f := newFakeAPI()
		f.statusErr = fmt.Errorf("localapi: GET /v1/status: %w", enoent)
		return f
	}
	a := &app{d: d}
	_, _, err := a.findDaemon(context.Background())
	if !isNoDaemon(err) {
		t.Fatalf("err = %v, want no daemon", err)
	}
}

// ---- porthole daemon under the Windows service manager ----

func TestDaemonRunsAsAService(t *testing.T) {
	s := newSvcTest(t)
	tok := testToken(t)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := saveConfig(cfg, fileConfig{Server: testServer, Token: tok}); err != nil {
		t.Fatal(err)
	}
	reload := make(chan struct{}, 1)
	readyCalled := false
	s.d.isService = func() (bool, error) { return true, nil }
	var svcName string
	s.d.runService = func(name string, run func(context.Context, func(), <-chan struct{}) error) error {
		svcName = name
		return run(context.Background(), func() { readyCalled = true }, reload)
	}
	var got daemon.Options
	s.d.runDaemon = func(_ context.Context, o daemon.Options) error {
		got = o
		if sent, err := o.Notify(localapi.NotifyReady); !sent || err != nil {
			t.Errorf("Notify(READY) = %v, %v", sent, err)
		}
		o.Logger.Info("hello from the daemon")
		return nil
	}

	_, _, err := execute(t, s.d, "--config", cfg, "--socket", `\\.\pipe\ProtectedPrefix\Administrators\porthole`,
		"daemon", "--allow", "devs")
	if err != nil {
		t.Fatal(err)
	}
	if svcName != service.DefaultName || !readyCalled {
		t.Errorf("service name = %q, ready called = %v", svcName, readyCalled)
	}
	if got.Reload == nil || got.Token != tok || len(got.SocketAllow) != 1 || got.SocketAllow[0] != "devs" {
		t.Errorf("daemon options = %+v", got)
	}
	logPath := serviceLogPath(s.d.getenv)
	data, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(data), "hello from the daemon") {
		t.Errorf("service log %s = %q, %v", logPath, data, err)
	}
}

func TestDaemonAsAServiceReportsABrokenConfig(t *testing.T) {
	s := newSvcTest(t)
	s.d.isService = func() (bool, error) { return true, nil }
	s.d.runService = func(_ string, run func(context.Context, func(), <-chan struct{}) error) error {
		return run(context.Background(), func() { t.Error("ready called for a broken configuration") }, nil)
	}
	s.d.runDaemon = func(context.Context, daemon.Options) error { t.Error("the daemon ran"); return nil }
	_, _, err := execute(t, s.d, "--config", filepath.Join(t.TempDir(), "none.yaml"), "daemon")
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitConfig {
		t.Fatalf("err = %v, want a configuration error", err)
	}
	data, _ := os.ReadFile(serviceLogPath(s.d.getenv))
	if !strings.Contains(string(data), "invalid configuration") {
		t.Errorf("the reason is not in the service log: %q", data)
	}
}

func TestDaemonOutsideAServiceIsUnchanged(t *testing.T) {
	s := newSvcTest(t)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := saveConfig(cfg, fileConfig{Server: testServer, Token: testToken(t)}); err != nil {
		t.Fatal(err)
	}
	s.d.isService = func() (bool, error) { return false, nil }
	s.d.runService = func(string, func(context.Context, func(), <-chan struct{}) error) error {
		t.Error("runService called outside the service manager")
		return nil
	}
	var got daemon.Options
	s.d.runDaemon = func(_ context.Context, o daemon.Options) error { got = o; return nil }
	if _, _, err := execute(t, s.d, "--config", cfg, "--socket", "/x/s.sock", "daemon"); err != nil {
		t.Fatal(err)
	}
	if got.Reload != nil || got.SocketPath != "/x/s.sock" {
		t.Errorf("options = %+v", got)
	}
}

func TestRotatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "porthole.log")
	r, err := openRotatingFile(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	line := strings.Repeat("a", 59) + "\n" // 60 bytes
	for range 5 {
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{path, path + ".1"} {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() > 100 {
			t.Errorf("%s: %v, %v", p, fi, err)
		}
	}
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Error("more than one rotated copy")
	}
	// A restart appends.
	_ = r.Close()
	r2, err := openRotatingFile(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if r2.size != 60 {
		t.Errorf("size after reopen = %d, want 60", r2.size)
	}
}

func TestServiceLogPath(t *testing.T) {
	got := serviceLogPath(func(k string) string {
		if k == "ProgramData" {
			return filepath.Join("X", "pd")
		}
		return ""
	})
	if want := filepath.Join("X", "pd", "porthole", "logs", "porthole.log"); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// `porthole http <port>` with no daemon anywhere runs in this process (found live on Windows with v0.3.0-alpha.2: the
// AF_UNIX dial of a missing socket was reported as a daemon that "does not answer properly"). The endpoints are the
// real ones: on Windows the named pipes, elsewhere the default sockets, plus a stale $PORTHOLE_SOCKET that points
// at a socket file in a directory that does not exist.
func TestHTTPWithoutADaemonRunsInProcess(t *testing.T) {
	stale := filepath.Join(t.TempDir(), "no", "such", "dir", "porthole.sock")
	for name, env := range map[string]map[string]string{
		"default endpoints":      nil,
		"stale $PORTHOLE_SOCKET": {envSocket: stale},
	} {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS != "windows" && env == nil {
				t.Skip("the default endpoints of this OS may belong to a daemon on a developer machine")
			}
			path := writeConfig(t, testServer, testToken(t))
			d := testDeps(env)
			d.socketPaths = localapi.DefaultSocketPaths
			if env != nil { // only the stale path: a daemon of the developer machine must not answer
				d.socketPaths = func() []string { return nil }
			}
			d.userSocket = localapi.UserSocketPath
			d.dial = func(p string) apiClient { return localapi.NewClient(p) }
			ran := false
			d.run = func(context.Context, client.Options) error { ran = true; return nil }

			_, stderr, err := execute(t, d, "--config", path, "http", "8080")
			if err != nil || !ran {
				t.Fatalf("err = %v, ran = %v, stderr %q: want the in-process fallback", err, ran, stderr)
			}
		})
	}
}
