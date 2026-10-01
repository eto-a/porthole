// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

// executeExit runs args the way main does (exitcode.Run) and returns the output and the exit status.
func executeExit(t *testing.T, d deps, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	root := newRoot("1.2.3", d)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	code = exitcode.Run(context.Background(), root, "porthole", args, classify)
	return out.String(), errOut.String(), code
}

// jsonLines parses stdout as JSON Lines and fails if any line is not a JSON object.
func jsonLines(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout line %q is not a JSON object: %v\nstdout:\n%s", line, err, stdout)
		}
		docs = append(docs, m)
	}
	return docs
}

// jsonDoc parses stdout as exactly one JSON object.
func jsonDoc(t *testing.T, stdout string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\nstdout:\n%s", err, stdout)
	}
	return m
}

func errorDoc(t *testing.T, stdout string) (code, message string) {
	t.Helper()
	m := jsonDoc(t, stdout)
	e, ok := m["error"].(map[string]any)
	if !ok || len(m) != 1 {
		t.Fatalf("not an error document: %s", stdout)
	}
	code, _ = e["code"].(string)
	message, _ = e["message"].(string)
	return code, message
}

func TestJSONStandaloneEvents(t *testing.T) {
	d := testDeps(nil)
	d.run = func(_ context.Context, opts client.Options) error {
		opts.OnEvent(client.Connected{ClientName: "home"})
		opts.OnEvent(client.TunnelReady{
			Spec: opts.Tunnels[0], Name: "web", PublicURL: "https://web-home.tun.example.com",
		})
		opts.OnEvent(client.Disconnected{Err: errors.New("eof"), RetryIn: 1500 * time.Millisecond})
		opts.OnEvent(client.TunnelClosed{Name: "web", Reason: "name_taken: gone"})
		return nil
	}
	stdout, _, code := executeExit(t, d, "--json", "http", "8080", "--name", "web", "--no-daemon",
		"--server", "https://tun.example.com", "--token", testToken(t))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	ev := jsonLines(t, stdout)
	if len(ev) != 4 {
		t.Fatalf("%d events, want 4:\n%s", len(ev), stdout)
	}
	if ev[0]["event"] != "connected" || ev[0]["client"] != "home" {
		t.Errorf("connected: %v", ev[0])
	}
	r := ev[1]
	if r["event"] != "tunnel_ready" || r["name"] != "web" || r["kind"] != "http" || r["local_addr"] != "127.0.0.1:8080" ||
		r["public_url"] != "https://web-home.tun.example.com" || r["private"] != false {
		t.Errorf("tunnel_ready: %v", r)
	}
	if ev[2]["event"] != "disconnected" || ev[2]["error"] != "eof" || ev[2]["retry_in_ms"] != float64(1500) {
		t.Errorf("disconnected: %v", ev[2])
	}
	if ev[3]["event"] != "tunnel_closed" || ev[3]["name"] != "web" || ev[3]["reason"] != "name_taken: gone" {
		t.Errorf("tunnel_closed: %v", ev[3])
	}
}

func TestJSONSSHReadyHasTheJump(t *testing.T) {
	d := testDeps(nil)
	d.run = func(_ context.Context, opts client.Options) error {
		opts.OnEvent(client.Connected{ClientName: "home"})
		opts.OnEvent(client.TunnelReady{Spec: opts.Tunnels[0], Name: "ssh", SSHJump: "tun.example.com:2222"})
		return nil
	}
	stdout, _, code := executeExit(t, d, "--json", "ssh", "--private", "--no-daemon",
		"--server", "https://tun.example.com", "--token", testToken(t))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	r := jsonLines(t, stdout)[1]
	if r["kind"] != "ssh" || r["ssh_jump"] != "tun.example.com:2222" || r["private"] != true {
		t.Errorf("tunnel_ready: %v", r)
	}
	if _, has := r["public_url"]; has {
		t.Errorf("an ssh tunnel has no public_url: %v", r)
	}
}

func TestJSONAttachEvents(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	f := newFakeAPI()
	f.attachEvents = readyEvents("blog", "127.0.0.1:8080", "https://blog-home.tun.example.com")
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	stdout, _, err := runAttached(t, d, f, "--config", path, "--json", "http", "8080", "--name", "blog")
	if err != nil {
		t.Fatal(err)
	}
	ev := jsonLines(t, stdout)
	if len(ev) != 2 || ev[0]["event"] != "connected" || ev[1]["event"] != "tunnel_ready" || ev[1]["name"] != "blog" {
		t.Errorf("events: %s", stdout)
	}
}

func TestJSONDetachPrintsTheTunnel(t *testing.T) {
	f := newFakeAPI()
	ready := localapi.Tunnel{
		Name: "blog", Type: "http", LocalAddr: "127.0.0.1:80", PublicURL: "https://blog-home.tun.example.com",
		State: localapi.TunnelReady, Lifetime: localapi.LifetimeRuntime,
	}
	f.addResult = ready
	f.tunnels = []localapi.Tunnel{ready}
	stdout, _, code := executeExit(t, daemonWith(f), "--json", "http", "80", "--name", "blog", "--detach")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	m := jsonDoc(t, stdout)
	if m["name"] != "blog" || m["state"] != "ready" || m["public_url"] != "https://blog-home.tun.example.com" {
		t.Errorf("tunnel object: %v", m)
	}
}

func TestJSONLogin(t *testing.T) {
	path := writeConfig(t, "", "")
	tok := testToken(t)
	stdout, _, code := executeExit(t, testDeps(nil), "--config", path, "--json", "login", "--check", "https://tun.example.com", tok)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(stdout, tok) {
		t.Errorf("the token must not be printed:\n%s", stdout)
	}
	m := jsonDoc(t, stdout)
	chk, _ := m["check"].(map[string]any)
	if m["saved"] != true || m["server"] != "https://tun.example.com" || m["config"] != path || chk["client_name"] != "home" {
		t.Errorf("login result: %v", m)
	}
	stdout, _, code = executeExit(t, testDeps(nil), "--config", path, "--json", "login", "https://tun.example.com", tok)
	if m := jsonDoc(t, stdout); code != 0 || m["saved"] != true || m["check"] != nil {
		t.Errorf("login without --check: exit %d, %v", code, m)
	}
}

func TestJSONReloadAndClose(t *testing.T) {
	f := newFakeAPI()
	f.reloadRes = localapi.ReloadResult{Added: []string{"a"}}
	stdout, _, code := executeExit(t, daemonWith(f), "--json", "reload")
	m := jsonDoc(t, stdout)
	if code != 0 || m["added"].([]any)[0] != "a" || len(m["removed"].([]any)) != 0 {
		t.Errorf("reload: exit %d, %s", code, stdout)
	}

	f.reloadRes = localapi.ReloadResult{Errors: map[string]string{"db": "port_unavailable: taken"}}
	stdout, _, code = executeExit(t, daemonWith(f), "--json", "reload")
	m = jsonDoc(t, stdout) // exactly one document, even though the command fails
	if code != exitcode.Rejected || m["errors"].(map[string]any)["db"] == nil {
		t.Errorf("reload with errors: exit %d, %s", code, stdout)
	}

	stdout, _, code = executeExit(t, daemonWith(f), "--json", "close", "blog")
	if m := jsonDoc(t, stdout); code != 0 || m["closed"] != "blog" {
		t.Errorf("close: exit %d, %s", code, stdout)
	}
}

func TestJSONVersion(t *testing.T) {
	stdout, _, code := executeExit(t, testDeps(nil), "--json", "version")
	if m := jsonDoc(t, stdout); code != 0 || m["name"] != "porthole" || m["version"] != "1.2.3" {
		t.Errorf("version: exit %d, %s", code, stdout)
	}
}

func TestExitStatusAndErrorDocument(t *testing.T) {
	denied := newFakeAPI()
	denied.statusErr = errPerm
	deniedDeps, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": denied}, "/s/user")

	failing := func(err error) deps {
		d := testDeps(nil)
		d.run = func(context.Context, client.Options) error { return err }
		return d
	}
	standalone := []string{"http", "8080", "--no-daemon", "--server", "https://tun.example.com", "--token", testToken(t)}

	rejected := newFakeAPI()
	rejected.attachEvents = []localapi.Event{
		{Type: localapi.EventAttached, Name: "web", Tunnel: &localapi.Tunnel{Name: "web"}},
		{Type: localapi.EventTunnelClosed, Name: "web", Reason: "limit_exceeded: too many tunnels", Error: "x"},
	}
	rejectedDeps, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": rejected}, "/s/user")
	cfgPath := writeConfig(t, "https://tun.example.com", testToken(t))

	tests := []struct {
		name     string
		d        deps
		args     []string
		wantCode int
		wantErr  string // "code" of the error document
	}{
		{
			"connect", failing(&client.InitialConnectError{URL: "https://x", Attempts: 3, Err: errors.New("refused")}),
			standalone, exitcode.Connect, "connect_failed",
		},
		{"revoked", failing(&proto.Error{Code: proto.CodeTokenRevoked, Message: "x"}), standalone, exitcode.Auth, "token_revoked"},
		{"expired", failing(&proto.Error{Code: proto.CodeTokenExpired}), standalone, exitcode.Auth, "token_expired"},
		{"unauthorized", failing(&proto.Error{Code: proto.CodeUnauthorized}), standalone, exitcode.Auth, "unauthorized"},
		{"name taken", failing(&proto.Error{Code: proto.CodeNameTaken}), standalone, exitcode.Rejected, "name_taken"},
		{"forbidden", failing(&proto.Error{Code: proto.CodeForbidden}), standalone, exitcode.Rejected, "forbidden"},
		{"port", failing(&proto.Error{Code: proto.CodePortUnavailable}), standalone, exitcode.Rejected, "port_unavailable"},
		{"limit", failing(&proto.Error{Code: proto.CodeLimitExceeded}), standalone, exitcode.Rejected, "limit_exceeded"},
		{
			"limit via the daemon", rejectedDeps,
			[]string{"--config", cfgPath, "http", "8080", "--name", "web"},
			exitcode.Rejected, "limit_exceeded",
		},
		{"other server error", failing(&proto.Error{Code: proto.CodeInternal}), standalone, exitcode.General, "internal"},
		{"plain error", failing(errors.New("boom")), standalone, exitcode.General, "error"},
		{"no daemon", testDeps(nil), []string{"status"}, exitcode.Daemon, "daemon_unavailable"},
		{"daemon socket denied", deniedDeps, []string{"status"}, exitcode.Daemon, "permission_denied"},
		{
			"no credentials", testDeps(nil),
			[]string{"--config", cfgPath + ".missing", "http", "8080", "--no-daemon"},
			exitcode.Config, "config",
		},
		{"unknown flag", testDeps(nil), []string{"http", "8080", "--bogus"}, exitcode.Usage, "usage"},
		{"missing argument", testDeps(nil), []string{"http"}, exitcode.Usage, "usage"},
		{"unknown command", testDeps(nil), []string{"frobnicate"}, exitcode.Usage, "usage"},
		{"bad port", testDeps(nil), []string{"http", "99999", "--no-daemon"}, exitcode.Usage, "usage"},
		{"exclusive flags", testDeps(nil), []string{"http", "80", "--daemon", "--no-daemon"}, exitcode.Usage, "usage"},
		{"bad token", testDeps(nil), []string{"--config", cfgPath, "login", "https://tun.example.com", "nope"}, exitcode.Usage, "usage"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.args
			_, stderr, code := executeExit(t, tc.d, args...)
			if code != tc.wantCode {
				t.Fatalf("text mode: exit %d, want %d (stderr %q)", code, tc.wantCode, stderr)
			}
			if !strings.HasPrefix(stderr, "porthole: ") {
				t.Errorf("text mode: stderr %q lacks the program prefix", stderr)
			}
			// The same failure with --json.
			stdout, stderr, code := executeExit(t, tc.d, append([]string{"--json"}, args...)...)
			if code != tc.wantCode {
				t.Fatalf("--json: exit %d, want %d", code, tc.wantCode)
			}
			if got, msg := errorDoc(t, stdout); got != tc.wantErr || msg == "" {
				t.Errorf("--json: error code %q (message %q), want %q\n%s", got, msg, tc.wantErr, stdout)
			}
			if stderr != "" {
				t.Errorf("--json: stderr should stay empty, got %q", stderr)
			}
		})
	}
}

func TestExitCodeOfClassifiedErrors(t *testing.T) {
	for err, want := range map[error]int{
		&client.InitialConnectError{Err: errors.New("x")}:                          exitcode.Connect,
		&explainedError{msg: "m", err: &proto.Error{Code: proto.CodeTokenRevoked}}: exitcode.Auth,
		&noDaemonError{}:                               exitcode.Daemon,
		&deniedError{path: "/s"}:                       exitcode.Daemon,
		localapi.NewError(localapi.CodeNameTaken, "x"): exitcode.Rejected,
		localapi.NewError(localapi.CodeNotFound, "x"):  exitcode.General,
	} {
		if got := ExitCode(err); got != want {
			t.Errorf("ExitCode(%v) = %d, want %d", err, got, want)
		}
	}
}
