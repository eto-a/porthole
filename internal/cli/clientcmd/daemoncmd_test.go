// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/daemon"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

// captureDaemon makes `porthole daemon` record its options instead of running.
func captureDaemon(d deps, got *daemon.Options, result error) deps {
	d.runDaemon = func(_ context.Context, o daemon.Options) error {
		*got = o
		return result
	}
	return d
}

func TestDaemonCommandOptions(t *testing.T) {
	dir := t.TempDir()
	tok := testToken(t)
	cfg := filepath.Join(dir, "config.yaml")
	if err := saveConfig(cfg, fileConfig{Server: "https://cfg.example.com", Token: tok}); err != nil {
		t.Fatal(err)
	}

	var got daemon.Options
	d := captureDaemon(testDeps(nil), &got, nil)
	d.userSocket = func() string { return "/run/user/1000/porthole/porthole.sock" }

	// Defaults: tunnels.yaml next to the config file, the user socket, mode 0600, credentials from the config file.
	if _, _, err := execute(t, d, "--config", cfg, "daemon"); err != nil {
		t.Fatal(err)
	}
	want := daemon.Options{
		ConfigServer: "https://cfg.example.com", Token: tok, TunnelsPath: filepath.Join(dir, "tunnels.yaml"),
		SocketPath: "/run/user/1000/porthole/porthole.sock", SocketMode: 0o600, Version: "1.2.3",
	}
	got.Logger = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("options\n got %+v\nwant %+v", got, want)
	}

	// The invocation of the systemd unit: all three paths given, the system socket is shared with the group.
	if _, _, err := execute(t, d, "daemon", "--config", cfg, "--tunnels", "/etc/porthole/tunnels.yaml",
		"--socket", "/run/porthole/porthole.sock"); err != nil {
		t.Fatal(err)
	}
	if got.TunnelsPath != "/etc/porthole/tunnels.yaml" || got.SocketPath != localapi.SystemSocketPath || got.SocketMode != 0o660 {
		t.Errorf("options %+v", got)
	}

	// $PORTHOLE_SOCKET, and the environment for the server and token (explicit server wins over the config file).
	envTok := testToken(t)
	d2 := captureDaemon(testDeps(map[string]string{envSocket: "/s/env", envServer: "https://env.example.com", envToken: envTok}), &got, nil)
	if _, _, err := execute(t, d2, "--config", cfg, "daemon"); err != nil {
		t.Fatal(err)
	}
	if got.SocketPath != "/s/env" || got.ServerURL != "https://env.example.com" || got.Token != envTok || got.SocketMode != 0o600 {
		t.Errorf("options %+v", got)
	}
	// --socket beats the environment.
	if _, _, err := execute(t, d2, "--config", cfg, "--socket", "/s/flag", "daemon"); err != nil || got.SocketPath != "/s/flag" {
		t.Errorf("err = %v, options %+v", err, got)
	}
}

func TestDaemonCommandUsesTokenFile(t *testing.T) {
	dir := t.TempDir()
	tok := testToken(t)
	writeTokenFile(t, dir, "token", tok+"\n", 0o600)
	cfg := writeRawConfig(t, dir, "server: https://tun.example.com\ntoken_file: token\n")
	var got daemon.Options
	d := captureDaemon(testDeps(nil), &got, nil)
	if _, _, err := execute(t, d, "--config", cfg, "--socket", "/s/x", "daemon"); err != nil || got.Token != tok {
		t.Fatalf("err = %v, options %+v", err, got)
	}
}

func TestDaemonConfigErrorsExit78(t *testing.T) {
	dir := t.TempDir()
	good := writeConfig(t, "https://tun.example.com", testToken(t))
	missing := filepath.Join(dir, "none.yaml")
	garbage := filepath.Join(dir, "garbage.yaml")
	if err := os.WriteFile(garbage, []byte("{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	d := testDeps(nil)
	d.userSocket = func() string { return "/s/user" }
	d.runDaemon = func(context.Context, daemon.Options) error { called = true; return nil }

	for name, args := range map[string][]string{
		"no credentials":  {"--config", missing, "daemon"},
		"unreadable yaml": {"--config", garbage, "daemon"},
		"no socket":       {"--config", good, "daemon"}, // set below: userSocket returns ""
		"malformed token": {"--config", writeConfig(t, "https://tun.example.com", "garbage"), "daemon"},
	} {
		dd := d
		if name == "no socket" {
			dd.userSocket = func() string { return "" }
		}
		_, _, err := execute(t, dd, args...)
		if err == nil || ExitCode(err) != ExitConfig {
			t.Errorf("%s: err = %v, exit code %d, want %d", name, err, ExitCode(err), ExitConfig)
		}
	}
	if called {
		t.Error("the daemon started despite a configuration error")
	}

	// Errors of the daemon itself: ConfigError (broken tunnels file, rejected token) is 78, the rest is 1.
	for name, tt := range map[string]struct {
		err  error
		want int
	}{
		"config error":  {&daemon.ConfigError{Err: errors.New("tunnels file x: bad")}, ExitConfig},
		"token refused": {&daemon.ConfigError{Err: &proto.Error{Code: proto.CodeTokenRevoked, Message: "x"}}, ExitConfig},
		"other":         {errors.New("listen failed"), 1},
		"already":       {localapi.ErrAlreadyRunning, 1},
	} {
		d2 := testDeps(nil)
		d2.runDaemon = func(context.Context, daemon.Options) error { return tt.err }
		_, _, err := execute(t, d2, "--config", good, "--socket", "/s/x", "daemon")
		if err == nil || ExitCode(err) != tt.want {
			t.Errorf("%s: err = %v, exit code %d, want %d", name, err, ExitCode(err), tt.want)
		}
	}

	// A rejected token is explained like in the foreground client, and the original error stays reachable.
	d3 := testDeps(nil)
	perr := &proto.Error{Code: proto.CodeTokenRevoked, Message: "revoked"}
	d3.runDaemon = func(context.Context, daemon.Options) error { return &daemon.ConfigError{Err: perr} }
	_, _, err := execute(t, d3, "--config", good, "--socket", "/s/x", "daemon")
	var got *proto.Error
	if err == nil || !strings.Contains(err.Error(), "porthole login") || !errors.As(err, &got) || got != perr {
		t.Errorf("err = %v", err)
	}
}

func TestExitCode(t *testing.T) {
	if ExitCode(nil) != 0 || ExitCode(errors.New("x")) != 1 {
		t.Error("nil exits with 0, plain errors with 1")
	}
	if got := ExitCode(&ExitError{Code: 78, Err: errors.New("x")}); got != 78 {
		t.Errorf("got %d", got)
	}
	wrapped := &explainedError{msg: "m", err: &ExitError{Code: 78, Err: errors.New("x")}}
	if got := ExitCode(wrapped); got != 78 {
		t.Errorf("a wrapped ExitError: got %d", got)
	}
	if got := ExitCode(&ExitError{Code: 0, Err: errors.New("x")}); got != 1 {
		t.Errorf("a zero code must not mean success: got %d", got)
	}
}

const startFile = `version: 1
tunnels:
  blog:
    type: http
    addr: 3000
  db:
    type: tcp
    addr: nas.local:5432
    remote_port: 20017
  off:
    type: http
    addr: 9999
    enabled: false
`

func writeTunnelsFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tunnels.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStartRunsTheEnabledTunnelsInProcess(t *testing.T) {
	cfg := writeConfig(t, "https://cfg.example.com", testToken(t))
	file := writeTunnelsFile(t, startFile)
	var got client.Options
	d := capture(testDeps(nil), &got,
		client.TunnelReady{Spec: client.TunnelSpec{Name: "blog", LocalAddr: "127.0.0.1:3000"}, Name: "blog", PublicURL: "https://blog-home.tun.example.com"},
		client.TunnelReady{Spec: client.TunnelSpec{Name: "db", LocalAddr: "nas.local:5432"}, Name: "db", PublicURL: "tcp://tun.example.com:20017"},
	)
	stdout, _, err := execute(t, d, "--config", cfg, "start", "--tunnels", file)
	if err != nil {
		t.Fatal(err)
	}
	want := []client.TunnelSpec{
		{Kind: "http", Name: "blog", LocalAddr: "127.0.0.1:3000"},
		{Kind: "tcp", Name: "db", LocalAddr: "nas.local:5432", RemotePort: 20017},
	}
	if len(got.Tunnels) != 2 || got.Tunnels[0] != want[0] || got.Tunnels[1] != want[1] {
		t.Errorf("tunnels %+v, want %+v", got.Tunnels, want)
	}
	if got.ServerURL != "https://cfg.example.com" || got.Version != "1.2.3" || got.MaxInitialAttempts != client.DefaultMaxInitialAttempts {
		t.Errorf("options %+v", got)
	}
	if !strings.Contains(stdout, "blog: https://blog-home.tun.example.com -> 127.0.0.1:3000\n") ||
		!strings.Contains(stdout, "db: tcp://tun.example.com:20017 -> nas.local:5432\n") {
		t.Errorf("stdout %q", stdout)
	}
}

func TestStartNamesAndDefaultPath(t *testing.T) {
	cfg := writeConfig(t, "https://cfg.example.com", testToken(t))
	// tunnels.yaml next to the config file is the default.
	if err := os.WriteFile(filepath.Join(filepath.Dir(cfg), "tunnels.yaml"), []byte(startFile), 0o600); err != nil {
		t.Fatal(err)
	}
	var got client.Options
	d := capture(testDeps(nil), &got)
	if _, _, err := execute(t, d, "--config", cfg, "start", "off", "blog"); err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 2 || got.Tunnels[0].Name != "blog" || got.Tunnels[1].Name != "off" {
		t.Errorf("named tunnels (a disabled one included): %+v", got.Tunnels)
	}
	_, _, err := execute(t, d, "--config", cfg, "start", "nope")
	if err == nil || !strings.Contains(err.Error(), `"nope" is not defined`) {
		t.Errorf("unknown name: err = %v", err)
	}
}

func TestStartServerPrecedence(t *testing.T) {
	cfg := writeConfig(t, "https://cfg.example.com", testToken(t))
	file := writeTunnelsFile(t, "version: 1\nserver: https://file.example.com\ntunnels:\n  a: {type: http, addr: 1}\n")
	var got client.Options

	// the tunnels file beats the config file ...
	if _, _, err := execute(t, capture(testDeps(nil), &got), "--config", cfg, "start", "--tunnels", file); err != nil || got.ServerURL != "https://file.example.com" {
		t.Fatalf("file: err = %v, %+v", err, got)
	}
	// ... the environment beats the file ... and the flag beats the environment.
	d := capture(testDeps(map[string]string{envServer: "https://env.example.com"}), &got)
	if _, _, err := execute(t, d, "--config", cfg, "start", "--tunnels", file); err != nil || got.ServerURL != "https://env.example.com" {
		t.Fatalf("env: err = %v, %+v", err, got)
	}
	if _, _, err := execute(t, d, "--config", cfg, "start", "--tunnels", file, "--server", "https://flag.example.com"); err != nil ||
		got.ServerURL != "https://flag.example.com" {
		t.Fatalf("flag: err = %v, %+v", err, got)
	}
}

func TestStartProblems(t *testing.T) {
	cfg := writeConfig(t, "https://cfg.example.com", testToken(t))
	ran := false
	d := testDeps(nil)
	d.run = func(context.Context, client.Options) error { ran = true; return nil }

	if _, _, err := execute(t, d, "--config", cfg, "start", "--tunnels", filepath.Join(t.TempDir(), "none.yaml")); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing file: err = %v", err)
	}
	if _, _, err := execute(t, d, "--config", cfg, "start", "--tunnels", writeTunnelsFile(t, "version: 1\n")); err == nil ||
		!strings.Contains(err.Error(), "no enabled tunnels") {
		t.Errorf("empty file: err = %v", err)
	}
	bad := writeTunnelsFile(t, "version: 1\ntunnels:\n  a: {type: nope, addr: 1}\n")
	if _, _, err := execute(t, d, "--config", cfg, "start", "--tunnels", bad); err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("bad file: err = %v", err)
	}
	if _, _, err := execute(t, d, "--config", filepath.Join(t.TempDir(), "none.yaml"), "start", "--tunnels", writeTunnelsFile(t, startFile)); err == nil ||
		!strings.Contains(err.Error(), "porthole login") {
		t.Errorf("no credentials: err = %v", err)
	}
	if ran {
		t.Error("the client ran despite the errors")
	}
}

func TestStartWarnsAboutARunningDaemon(t *testing.T) {
	cfg := writeConfig(t, "https://cfg.example.com", testToken(t))
	file := writeTunnelsFile(t, startFile)
	var got client.Options
	d, _ := withSockets(capture(testDeps(nil), &got), map[string]*fakeAPI{"/s/user": newFakeAPI()}, "/s/user")
	_, stderr, err := execute(t, d, "--config", cfg, "start", "--tunnels", file)
	if err != nil || len(got.Tunnels) != 2 {
		t.Fatalf("err = %v, %+v", err, got)
	}
	if !strings.Contains(stderr, "note: a porthole daemon is running (/s/user)") {
		t.Errorf("stderr %q", stderr)
	}
}
