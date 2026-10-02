// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/localapi"
)

// The daemon tests need the client of this working tree: an older release has no daemon.
func skipUnlessCurrentClient(t *testing.T) {
	t.Helper()
	if os.Getenv(envClientBin) != "" {
		t.Skip("the daemon needs the porthole client of the working tree")
	}
}

// daemonEnv is a running `porthole daemon` next to a server.
type daemonEnv struct {
	*env
	t          *testing.T
	tok        string
	sock       string // short: the length of a unix socket path is limited to about 104 bytes
	tunnelsPth string
	proc       *proc
}

// startDaemon logs in, writes the tunnels file and starts the daemon. It returns once the socket answers.
func startDaemon(t *testing.T, e *env, tok, tunnels string) *daemonEnv {
	t.Helper()
	skipUnlessCurrentClient(t)
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	d := &daemonEnv{env: e, t: t, tok: tok, sock: filepath.Join(dir, "d.sock"), tunnelsPth: filepath.Join(dir, "tunnels.yaml")}
	run(t, porthole, "--config", e.clientConf, "login", e.server, tok)
	d.writeTunnels(tunnels)
	d.launch()
	return d
}

func (d *daemonEnv) writeTunnels(content string) {
	d.t.Helper()
	if err := os.WriteFile(d.tunnelsPth, []byte(content), 0o600); err != nil {
		d.t.Fatal(err)
	}
}

// launch starts the daemon process and waits for its socket.
func (d *daemonEnv) launch() {
	d.t.Helper()
	d.proc = start(d.t, porthole, "--config", d.clientConf, "daemon", "--tunnels", d.tunnelsPth, "--socket", d.sock)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := d.status(); err == nil {
			return
		}
		select {
		case <-d.proc.done:
			d.t.Fatalf("the daemon exited early (%v):\n%s", d.proc.err, d.proc.output())
		case <-time.After(100 * time.Millisecond):
		}
	}
	d.t.Fatalf("the daemon did not answer on %s:\n%s", d.sock, d.proc.output())
}

// cli runs `porthole <args> --socket <sock>` and returns its output.
func (d *daemonEnv) cli(args ...string) (string, error) {
	return output(porthole, append(args, "--socket", d.sock)...)
}

// output runs bin and returns its combined output.
func output(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

func (d *daemonEnv) mustCLI(args ...string) string {
	d.t.Helper()
	out, err := d.cli(args...)
	if err != nil {
		d.t.Fatalf("porthole %v: %v\n%s", args, err, out)
	}
	return out
}

func (d *daemonEnv) status() (localapi.Status, error) {
	out, err := d.cli("status", "--json")
	if err != nil {
		return localapi.Status{}, fmt.Errorf("%w: %s", err, out)
	}
	var st localapi.Status
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return localapi.Status{}, fmt.Errorf("status --json is not JSON: %w\n%s", err, out)
	}
	return st, nil
}

func (d *daemonEnv) tunnel(name string) (localapi.Tunnel, bool) {
	st, err := d.status()
	if err != nil {
		d.t.Fatal(err)
	}
	for i := range st.Tunnels {
		if st.Tunnels[i].Name == name {
			return st.Tunnels[i], true
		}
	}
	return localapi.Tunnel{}, false
}

// waitTunnel waits until the tunnel is ready and returns it.
func (d *daemonEnv) waitTunnel(name string) localapi.Tunnel {
	d.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if tn, ok := d.tunnel(name); ok && tn.State == localapi.TunnelReady {
			return tn
		}
		time.Sleep(150 * time.Millisecond)
	}
	d.t.Fatalf("tunnel %s did not become ready; status:\n%s", name, d.mustCLI("status"))
	return localapi.Tunnel{}
}

// waitConnected waits until the daemon has a session with the server, so the server can route requests to it.
func (d *daemonEnv) waitConnected() {
	d.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := d.status(); err == nil && st.State == localapi.StateConnected {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	d.t.Fatalf("the daemon did not connect; status:\n%s", d.mustCLI("status"))
}

// waitGone waits until the daemon no longer lists the tunnel.
func (d *daemonEnv) waitGone(name string) {
	d.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := d.tunnel(name); !ok {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	d.t.Fatalf("tunnel %s is still listed:\n%s", name, d.mustCLI("status"))
}

var labelRe = regexp.MustCompile(`^http://([a-z0-9-]+)\.localhost:\d+$`)

// label returns the host label of a tunnel's public URL.
func labelOf(t *testing.T, tn localapi.Tunnel) string {
	t.Helper()
	m := labelRe.FindStringSubmatch(tn.PublicURL)
	if m == nil {
		t.Fatalf("tunnel %s has public URL %q, want http://<label>.localhost:<port>", tn.Name, tn.PublicURL)
	}
	return m[1]
}

func (e *env) mustServe(t *testing.T, label string) {
	t.Helper()
	code, body := e.viaTunnel(t, label, "/hello")
	if code != http.StatusOK || !strings.HasPrefix(body, "hello via "+label+".localhost") {
		t.Fatalf("via %s: %d %q", label, code, body)
	}
}

func httpTunnels(port int, names ...string) string {
	var b strings.Builder
	b.WriteString("version: 1\ntunnels:\n")
	for _, n := range names {
		fmt.Fprintf(&b, "  %s:\n    type: http\n    addr: %d\n", n, port)
	}
	return b.String()
}

func TestDaemonServesTheTunnelsFileAndTheLocalAPI(t *testing.T) {
	e, tok := setup(t)
	httpPort, _ := backend(t)
	d := startDaemon(t, e, tok, httpTunnels(httpPort, "blog"))

	// 1. The tunnel of the file is up and serves traffic.
	blog := d.waitTunnel("blog")
	if blog.Source != localapi.SourceFile || blog.Lifetime != localapi.LifetimeFile || blog.Type != "http" {
		t.Errorf("blog: %+v", blog)
	}
	e.mustServe(t, labelOf(t, blog))
	st, err := d.status()
	if err != nil {
		t.Fatal(err)
	}
	if st.State != localapi.StateConnected || st.ClientName != "home" || st.TunnelsFile != d.tunnelsPth || st.Server != e.server {
		t.Errorf("status %+v", st)
	}
	if out := d.mustCLI("tunnels"); !strings.Contains(out, "blog") || !strings.Contains(out, "file") {
		t.Errorf("`porthole tunnels`:\n%s", out)
	}

	// 2. `porthole http` attaches a second tunnel through the daemon and prints what the in-process client prints.
	cli := start(t, porthole, "http", fmt.Sprint(httpPort), "--name", "second", "--socket", d.sock)
	label := cli.waitFor(t, httpURLRe, 20*time.Second)[1]
	if label != "second-home" {
		t.Fatalf("label %q", label)
	}
	e.mustServe(t, label)
	if tn, ok := d.tunnel("second"); !ok || tn.Lifetime != localapi.LifetimeAttached {
		t.Errorf("second: %+v, %v", tn, ok)
	}
	// ... and it disappears when the CLI is gone, however it died.
	_ = cli.cmd.Process.Kill()
	<-cli.done
	d.waitGone("second")
	if code, _ := e.viaTunnel(t, label, "/hello"); code != http.StatusNotFound {
		t.Errorf("after the CLI died: %d, want 404", code)
	}
	d.waitTunnel("blog") // the file tunnel was not disturbed

	// 3. Edit the file and reload.
	d.writeTunnels(httpTunnels(httpPort, "blog", "extra"))
	out := d.mustCLI("reload")
	if !strings.Contains(out, "1 added") || !strings.Contains(out, "extra") || !strings.Contains(out, "1 unchanged") {
		t.Errorf("reload output:\n%s", out)
	}
	e.mustServe(t, labelOf(t, d.waitTunnel("extra")))

	// 4. A broken file is rejected as a whole.
	d.writeTunnels("version: 1\ntunnels:\n  blog: {type: nope, addr: 1}\n")
	out, err = d.cli("reload")
	if err == nil || !strings.Contains(out, "unknown type") || !strings.Contains(out, "keeping the current tunnels") {
		t.Errorf("reload of a broken file: err = %v\n%s", err, out)
	}
	d.waitTunnel("blog")
	d.waitTunnel("extra")

	// 5. A tunnel of the file cannot be closed over the API.
	out, err = d.cli("close", "blog")
	if err == nil || !strings.Contains(out, "tunnels.yaml") || !strings.Contains(out, "porthole reload") {
		t.Errorf("close of a file tunnel: err = %v\n%s", err, out)
	}
	if _, ok := d.tunnel("blog"); !ok {
		t.Error("blog was removed")
	}
}

func TestDaemonDetachedTunnels(t *testing.T) {
	e, tok := setup(t)
	httpPort, tcpPort := backend(t)
	d := startDaemon(t, e, tok, "version: 1\n")

	// --detach prints the address once the tunnel is ready and exits; the tunnel stays.
	out := d.mustCLI("http", fmt.Sprint(httpPort), "--name", "det", "--detach")
	label := httpURLRe.FindStringSubmatch(out)
	if len(label) < 2 || label[1] != "det-home" {
		t.Fatalf("output of --detach:\n%s", out)
	}
	e.mustServe(t, label[1])
	if tn, ok := d.tunnel("det"); !ok || tn.Lifetime != localapi.LifetimeRuntime || tn.Source != localapi.SourceRuntime {
		t.Errorf("det: %+v, %v", tn, ok)
	}

	// The name is taken now.
	out, err := d.cli("http", fmt.Sprint(httpPort), "--name", "det", "--detach")
	if err == nil || !strings.Contains(out, "choose another one with --name") {
		t.Errorf("duplicate name: err = %v\n%s", err, out)
	}

	// A TCP tunnel through the daemon works as well, `ssh` prints the command line.
	out = d.mustCLI("ssh", "--local-port", fmt.Sprint(tcpPort), "--user", "tester", "--detach")
	m := sshCmdRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("output of ssh --detach:\n%s", out)
	}
	echo(t, m[1])

	// close removes runtime tunnels.
	d.mustCLI("close", "det")
	d.waitGone("det")
	if code, _ := e.viaTunnel(t, label[1], "/hello"); code != http.StatusNotFound {
		t.Errorf("after close: %d, want 404", code)
	}
}

func TestDaemonRestartKeepsOnlyTheFile(t *testing.T) {
	e, tok := setup(t)
	httpPort, _ := backend(t)
	d := startDaemon(t, e, tok, httpTunnels(httpPort, "blog"))
	d.waitTunnel("blog")
	d.mustCLI("http", fmt.Sprint(httpPort), "--name", "temp", "--detach")

	// Kill the daemon the hard way: the stale socket file must not stop the next one from starting.
	_ = d.proc.cmd.Process.Kill()
	<-d.proc.done
	d.launch()
	d.waitTunnel("blog")
	if _, ok := d.tunnel("temp"); ok {
		t.Error("a runtime tunnel survived a daemon restart")
	}

	// A second daemon on the same socket refuses to start.
	out, err := output(porthole, "--config", d.clientConf, "daemon", "--tunnels", d.tunnelsPth, "--socket", d.sock)
	if err == nil || !strings.Contains(out, "already listening") {
		t.Errorf("second daemon: err = %v\n%s", err, out)
	}
	d.waitTunnel("blog") // and the first one is fine
}

func TestDaemonBrokenFileExits78(t *testing.T) {
	skipUnlessCurrentClient(t)
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	conf := filepath.Join(dir, "config.yaml")
	tok := "ph_" + strings.Repeat("a", 12) + "_" + strings.Repeat("b", 52)
	if err := os.WriteFile(conf, []byte("server: http://127.0.0.1:1\ntoken: "+tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tunnels := filepath.Join(dir, "tunnels.yaml")
	if err := os.WriteFile(tunnels, []byte("version: 1\ntunnels:\n  blog: {type: nope, addr: 1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := output(porthole, "--config", conf, "daemon", "--tunnels", tunnels, "--socket", filepath.Join(dir, "d.sock"))
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 78 || !strings.Contains(out, "unknown type") {
		t.Errorf("err = %v, output:\n%s", err, out)
	}

	// Without credentials it is a configuration error too.
	empty := filepath.Join(dir, "empty.yaml")
	out, err = output(porthole, "--config", empty, "daemon", "--tunnels", tunnels, "--socket", filepath.Join(dir, "d2.sock"))
	if !errors.As(err, &ee) || ee.ExitCode() != 78 || !strings.Contains(out, "porthole login") {
		t.Errorf("no credentials: err = %v, output:\n%s", err, out)
	}
}

func TestStartRunsTheTunnelsFileWithTokenFile(t *testing.T) {
	skipUnlessCurrentClient(t)
	e, tok := setup(t)
	httpPort, _ := backend(t)
	dir := t.TempDir()

	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(conf, []byte("server: "+e.server+"\ntoken_file: token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tunnels := filepath.Join(dir, "tunnels.yaml")
	if err := os.WriteFile(tunnels, []byte(httpTunnels(httpPort, "blog")), 0o600); err != nil {
		t.Fatal(err)
	}
	// --no-daemon is not needed: there is no daemon, and `start` never uses one.
	p := start(t, porthole, "--config", conf, "start", "--tunnels", tunnels)
	label := p.waitFor(t, regexp.MustCompile(`blog: http://([a-z0-9-]+)\.localhost:\d+ -> 127\.0\.0\.1:\d+`), 20*time.Second)[1]
	e.mustServe(t, label)
}
