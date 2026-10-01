// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/service"
)

// The service tests install the real thing: a systemd unit, a launchd job or a Windows service, so they change the
// machine. They run only in the `service` CI job (GitHub runners give root or Administrator), behind this variable.
// The job builds the binaries and this test once, and starts the system test under sudo on Unix.
const envService = "PORTHOLE_TEST_SERVICE"

func skipUnlessService(t *testing.T) {
	t.Helper()
	if os.Getenv(envService) != "1" {
		t.Skipf("set %s=1 to install a real service (it changes the machine)", envService)
	}
	skipInCompat(t, "the service needs the client of the working tree")
}

// svcResult is the part of `porthole service install|status --json` the tests read.
type svcResult struct {
	Config   string   `json:"config"`
	Tunnels  string   `json:"tunnels"`
	Socket   string   `json:"socket"`
	Warnings []string `json:"warnings"`
	Service  *struct {
		Installed bool   `json:"installed"`
		Running   bool   `json:"running"`
		PID       int    `json:"pid"`
		Detail    string `json:"detail"`
	} `json:"service"`
	API *struct {
		Socket string           `json:"socket"`
		Status *localapi.Status `json:"status"`
		Error  string           `json:"error"`
	} `json:"api"`
}

// runJSON runs bin with args and decodes its standard output (the standard error is kept apart) into v.
func runJSON(t *testing.T, v any, bin string, args ...string) {
	t.Helper()
	var stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %v: %v\nstdout: %s\nstderr: %s", filepath.Base(bin), args, err, out, stderr.String())
	}
	if err := json.Unmarshal(out, v); err != nil {
		t.Fatalf("%s %v printed no JSON: %v\n%s", filepath.Base(bin), args, err, out)
	}
}

// serviceStatus runs `service status --json` for the system service, or the per-user one.
func serviceStatus(exe string, user bool) (svcResult, error) {
	args := []string{"service", "status", "--json"}
	if user {
		args = append(args, "--user")
	}
	out, err := exec.Command(exe, args...).Output()
	if err != nil {
		return svcResult{}, fmt.Errorf("service status: %w", err)
	}
	var r svcResult
	if err := json.Unmarshal(out, &r); err != nil {
		return svcResult{}, fmt.Errorf("service status printed no JSON: %w\n%s", err, out)
	}
	return r, nil
}

// eventually polls cond every 250 ms until it holds; the last reason it did not is reported on timeout.
func eventually(t *testing.T, what string, timeout time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		ok, why := cond()
		if ok {
			return
		}
		last = why
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s: %s", timeout, what, last)
}

// waitServiceRunning waits until the service is running and its daemon is connected to the server.
func waitServiceRunning(t *testing.T, exe string, user bool) svcResult {
	t.Helper()
	var res svcResult
	eventually(t, "the service to run and the daemon to connect", 60*time.Second, func() (bool, string) {
		r, err := serviceStatus(exe, user)
		if err != nil {
			return false, err.Error()
		}
		res = r
		switch {
		case r.Service == nil || !r.Service.Installed:
			return false, "not installed"
		case !r.Service.Running:
			return false, "not running: " + r.Service.Detail
		case r.API == nil || r.API.Status == nil:
			if r.API != nil {
				return false, "API: " + r.API.Error
			}
			return false, "no API answer"
		case r.API.Status.State != localapi.StateConnected:
			return false, "daemon state " + r.API.Status.State
		}
		return true, ""
	})
	return res
}

// waitServiceStopped waits until the service is installed but no longer running.
func waitServiceStopped(t *testing.T, exe string) {
	t.Helper()
	eventually(t, "the service to stop", 30*time.Second, func() (bool, string) {
		r, err := serviceStatus(exe, false)
		if err != nil {
			return false, err.Error()
		}
		if r.Service != nil && r.Service.Running {
			return false, "still running"
		}
		return true, ""
	})
}

// waitNotServed waits until the server no longer routes the label to a client: 404 once it is gone, or 502 while the
// server keeps the name for its offline owner during the reconnect grace period (DESIGN §3.4).
func (e *env) waitNotServed(t *testing.T, label string) {
	t.Helper()
	eventually(t, "the server to drop "+label, 30*time.Second, func() (bool, string) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/hello", e.port), nil)
		req.Host = fmt.Sprintf("%s.localhost:%d", label, e.port)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, err.Error()
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadGateway, "status " + strconv.Itoa(resp.StatusCode)
	})
}

// installBinary puts a copy of the client where a system service may keep it: a service account cannot read the CI
// workspace (systemd's ProtectHome hides /home), and `service install` asks for the binary in its final place.
func installBinary(t *testing.T) string {
	t.Helper()
	dir := "/usr/local/bin"
	if runtime.GOOS == "windows" {
		dir = filepath.Join(os.Getenv("ProgramFiles"), "porthole")
	}
	dst := filepath.Join(dir, filepath.Base(porthole))
	if _, err := os.Stat(dst); err == nil { //nolint:gosec // the path is fixed by the test
		t.Fatalf("%s exists already; refusing to overwrite a real installation", dst)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a program directory is world-readable
		t.Fatal(err)
	}
	data, err := os.ReadFile(porthole)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil { //nolint:gosec // an executable
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if runtime.GOOS == "windows" {
			_ = os.RemoveAll(dir) //nolint:gosec // the path is fixed by the test
		} else {
			_ = os.Remove(dst) //nolint:gosec // the path is fixed by the test
		}
	})
	return dst
}

// dumpServiceLogs prints what the service logged, when the test failed.
func dumpServiceLogs(t *testing.T) {
	t.Helper()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("journalctl", "-u", "porthole", "--no-pager", "-n", "80")
	case "darwin":
		cmd = exec.Command("sh", "-c", "tail -n 80 /Library/Logs/porthole/*.log")
	case "windows":
		cmd = exec.Command("powershell", "-NoProfile", "-Command",
			`Get-Content -Tail 80 (Join-Path $env:ProgramData 'porthole\logs\porthole.log')`)
	default:
		return
	}
	out, err := cmd.CombinedOutput()
	t.Logf("service log (err=%v):\n%s", err, out)
}

// serviceGone checks, with the tools of the OS, that nothing of the service is left registered.
func serviceGone(t *testing.T) {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat("/etc/systemd/system/porthole.service"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the unit file is still there (stat: %v)", err)
		}
	case "darwin":
		if _, err := os.Stat("/Library/LaunchDaemons/io.github.eto-a.porthole.plist"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the plist is still there (stat: %v)", err)
		}
		if out, err := exec.Command("launchctl", "print", "system/io.github.eto-a.porthole").CombinedOutput(); err == nil {
			t.Errorf("launchd still knows the job:\n%s", out)
		}
	case "windows":
		// 1060: the specified service does not exist as an installed service.
		if out, err := exec.Command("sc.exe", "query", "porthole").CombinedOutput(); err == nil {
			t.Errorf("sc query still finds the service:\n%s", out)
		}
	}
}

// reloadService makes the daemon re-read its tunnels file the way each OS does it.
func reloadService(t *testing.T, exe, sock string) {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		run(t, "systemctl", "reload", "porthole")
	case "windows":
		run(t, "sc.exe", "control", "porthole", "paramchange")
	default: // launchd has no reload hook; the API does the same
		run(t, exe, "reload", "--socket", sock)
	}
}

// TestServiceSystem installs the system service from `porthole service install`, runs the daemon under the init
// system against a real server, and removes it again. Needs root or an elevated Windows terminal.
func TestServiceSystem(t *testing.T) {
	skipUnlessService(t)
	if !service.Elevated() {
		t.Skip("needs root (sudo) or an elevated Windows terminal")
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			t.Skip("systemd is not the init system of this machine")
		}
	}
	e, tok := setup(t)
	httpPort, _ := backend(t)
	exe := installBinary(t)

	// Credentials of the system service, then the service itself.
	var login struct {
		Config string `json:"config"`
	}
	runJSON(t, &login, exe, "login", "--system", "--json", e.server, tok)
	if login.Config == "" {
		t.Fatal("login --system reported no config path")
	}
	t.Cleanup(func() {
		if t.Failed() {
			dumpServiceLogs(t)
		}
	})
	t.Cleanup(func() { _ = exec.Command(exe, "service", "uninstall").Run() })

	var inst svcResult
	runJSON(t, &inst, exe, "service", "install", "--json")
	if inst.Socket != localapi.SystemSocketPath || inst.Tunnels == "" {
		t.Fatalf("service install: socket %q (want %q), tunnels %q", inst.Socket, localapi.SystemSocketPath, inst.Tunnels)
	}
	res := waitServiceRunning(t, exe, false)
	if res.Service.PID == 0 {
		t.Errorf("service status reports no PID: %+v", res.Service)
	}
	if res.API.Status.Server == "" || res.API.Status.ClientName != "home" {
		t.Errorf("daemon status = %+v, want a connection to %s as client home", res.API.Status, e.server)
	}

	// `porthole status` and a runtime tunnel go through the system endpoint, as for any user of the service.
	d := &daemonEnv{env: e, t: t, tok: tok, sock: inst.Socket}
	if out := d.mustCLI("status"); !strings.Contains(out, "connected") {
		t.Errorf("porthole status:\n%s", out)
	}
	d.mustCLI("http", fmt.Sprint(httpPort), "--name", "svc", "--detach")
	e.mustServe(t, labelOf(t, d.waitTunnel("svc")))

	// A tunnel added to the file reaches the running daemon through the reload of this OS.
	if err := os.WriteFile(inst.Tunnels, []byte(httpTunnels(httpPort, "filetun")), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadService(t, exe, inst.Socket)
	fileLabel := labelOf(t, d.waitTunnel("filetun"))
	e.mustServe(t, fileLabel)

	// stop ends the session and the runtime tunnel; start brings the file tunnel back.
	svcLabel := labelOf(t, d.waitTunnel("svc"))
	run(t, exe, "service", "stop")
	waitServiceStopped(t, exe)
	e.waitNotServed(t, svcLabel)
	run(t, exe, "service", "start")
	waitServiceRunning(t, exe, false)
	e.mustServe(t, labelOf(t, d.waitTunnel("filetun")))
	if _, ok := d.tunnel("svc"); ok {
		t.Error("the runtime tunnel survived a service restart")
	}

	// uninstall removes the registration (the config files stay) and ends the session.
	run(t, exe, "service", "uninstall")
	r, err := serviceStatus(exe, false)
	if err != nil || r.Service == nil || r.Service.Installed || r.Service.Running {
		t.Errorf("service status after uninstall = %+v, %v", r.Service, err)
	}
	serviceGone(t)
	e.waitNotServed(t, fileLabel)
	if _, err := os.Stat(login.Config); err != nil {
		t.Errorf("uninstall removed the configuration: %v", err)
	}
}

// TestServiceUser does the same with the per-user service (systemd user unit, LaunchAgent), as an unprivileged user.
// It skips where there is no user service manager: a CI runner may have no systemd user session or no login session.
func TestServiceUser(t *testing.T) {
	skipUnlessService(t)
	if service.Elevated() {
		t.Skip("run the user-service test without sudo")
	}
	switch runtime.GOOS {
	case "linux":
		if out, err := exec.Command("systemctl", "--user", "show-environment").CombinedOutput(); err != nil {
			t.Skipf("no systemd user manager (loginctl enable-linger and XDG_RUNTIME_DIR are needed): %v: %s", err, out)
		}
	case "darwin":
		if out, err := exec.Command("launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())).CombinedOutput(); err != nil { //nolint:gosec // a fixed command with the uid of this process
			t.Skipf("no GUI login session for a LaunchAgent: %v: %s", err, out)
		}
	default:
		t.Skipf("%s has no per-user service", runtime.GOOS)
	}
	e, tok := setup(t)
	httpPort, _ := backend(t)

	// The user's own config file lives in the test's directory, not in the home of the machine.
	run(t, porthole, "--config", e.clientConf, "login", e.server, tok)
	t.Cleanup(func() { _ = exec.Command(porthole, "--config", e.clientConf, "service", "uninstall", "--user").Run() }) //nolint:gosec // the test binary and its own config

	var inst svcResult
	runJSON(t, &inst, porthole, "--config", e.clientConf, "service", "install", "--user", "--json")
	if inst.Socket == "" {
		t.Fatal("service install --user reported no socket")
	}
	waitServiceRunning(t, porthole, true)

	d := &daemonEnv{env: e, t: t, tok: tok, sock: inst.Socket}
	d.mustCLI("http", fmt.Sprint(httpPort), "--name", "usr", "--detach")
	label := labelOf(t, d.waitTunnel("usr"))
	e.mustServe(t, label)

	run(t, porthole, "service", "uninstall", "--user")
	r, err := serviceStatus(porthole, true)
	if err != nil || r.Service == nil || r.Service.Installed || r.Service.Running {
		t.Errorf("service status --user after uninstall = %+v, %v", r.Service, err)
	}
	e.waitNotServed(t, label)
}
