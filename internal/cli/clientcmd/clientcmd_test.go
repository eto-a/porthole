// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/proto"
)

func testToken(t *testing.T) string {
	t.Helper()
	tok, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return tok.String()
}

// testDeps returns deps that never touch the real environment, network or user config.
func testDeps(env map[string]string) deps {
	return deps{
		run: func(context.Context, client.Options) error { return nil },
		check: func(context.Context, client.Options) (client.CheckResult, error) {
			return client.CheckResult{ClientName: "home", ServerVersion: "9.9"}, nil
		},
		getenv:        func(k string) string { return env[k] },
		userConfigDir: func() (string, error) { return "", errors.New("no user config dir in tests") },
		currentUser:   func() string { return "alice" },
	}
}

func execute(t *testing.T, d deps, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := newRoot("1.2.3", d)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func TestParseTarget(t *testing.T) {
	good := map[string]string{
		"8080":              "127.0.0.1:8080",
		"  22 ":             "127.0.0.1:22", //nolint:gocritic // surrounding whitespace is deliberate: parseTarget must trim it
		":3000":             "127.0.0.1:3000",
		"localhost:8080":    "localhost:8080",
		"192.168.1.5:9000":  "192.168.1.5:9000",
		"[::1]:8080":        "[::1]:8080",
		"nas.local:5432":    "nas.local:5432",
		"127.0.0.1:65535":   "127.0.0.1:65535",
		"host-with-dash:80": "host-with-dash:80",
	}
	for in, want := range good {
		got, err := parseTarget(in)
		if err != nil || got != want {
			t.Errorf("parseTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "65536", "-1", "http", "host:", "host:abc", "host:0", "::1", "a b:80", "host:80:90"} {
		if got, err := parseTarget(in); err == nil {
			t.Errorf("parseTarget(%q) = %q, want an error", in, got)
		}
	}
}

func TestLoginSavesConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "porthole")
	path := filepath.Join(dir, "config.yaml")
	token := testToken(t)

	stdout, _, err := execute(t, testDeps(nil), "--config", path, "login", "https://tun.example.com/", token)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, path) {
		t.Errorf("output %q does not mention the config path", stdout)
	}
	if strings.Contains(stdout, token) {
		t.Errorf("output leaks the token: %q", stdout)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "https://tun.example.com" || cfg.Token != token {
		t.Fatalf("stored config %+v", cfg)
	}

	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("config file mode = %v, %v; want 0600", fi.Mode().Perm(), err)
		}
		if di, err := os.Stat(dir); err != nil || di.Mode().Perm() != 0o700 {
			t.Errorf("config dir mode = %v, %v; want 0700", di.Mode().Perm(), err)
		}
	}

	// logging in again replaces the stored values and leaves no temp files behind
	token2 := testToken(t)
	if _, _, err := execute(t, testDeps(nil), "--config", path, "login", "http://127.0.0.1:8080", token2); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadConfig(path)
	if cfg.Server != "http://127.0.0.1:8080" || cfg.Token != token2 {
		t.Fatalf("stored config %+v", cfg)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("config dir has %d entries, want just the config file", len(entries))
	}
}

func TestLoginUsesUserConfigDir(t *testing.T) {
	base := t.TempDir()
	d := testDeps(nil)
	d.userConfigDir = func() (string, error) { return base, nil }
	if _, _, err := execute(t, d, "login", "https://tun.example.com", testToken(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "porthole", "config.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestLoginRejectsBadInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	token := testToken(t)
	cases := [][]string{
		{"login", "tun.example.com", token},
		{"login", "ftp://tun.example.com", token},
		{"login", "https://", token},
		{"login", "https://tun.example.com", "not-a-token"},
		{"login", "https://tun.example.com"},
	}
	for _, args := range cases {
		_, _, err := execute(t, testDeps(nil), append([]string{"--config", path}, args...)...)
		if err == nil {
			t.Errorf("%v: expected an error", args)
		}
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a config file was written for invalid input")
	}
}

func TestLoginCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	d := testDeps(nil)
	var gotOpts client.Options
	d.check = func(_ context.Context, o client.Options) (client.CheckResult, error) {
		gotOpts = o
		return client.CheckResult{ClientName: "home", ServerVersion: "9.9"}, nil
	}
	token := testToken(t)
	stdout, _, err := execute(t, d, "--config", path, "login", "--check", "https://tun.example.com", token)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `"home"`) || gotOpts.ServerURL != "https://tun.example.com" || gotOpts.Token != token {
		t.Fatalf("stdout %q, check options %+v", stdout, gotOpts)
	}

	d.check = func(context.Context, client.Options) (client.CheckResult, error) {
		return client.CheckResult{}, &proto.Error{Code: proto.CodeUnauthorized, Message: "unknown token"}
	}
	_, _, err = execute(t, d, "--config", path, "login", "--check", "https://tun.example.com", token)
	if err == nil || !strings.Contains(err.Error(), "porthole login") {
		t.Fatalf("err = %v, want a hint to log in again", err)
	}
	if cfg, _ := loadConfig(path); cfg.Token != token {
		t.Error("credentials should stay saved when only the check fails")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	if cfg, err := loadConfig(filepath.Join(dir, "missing.yaml")); err != nil || cfg != (fileConfig{}) {
		t.Fatalf("missing file: %+v, %v", cfg, err)
	}
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("server: https://x\ntoken: t\nbogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil {
		t.Error("unknown keys must be rejected")
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := loadConfig(p); err != nil || cfg != (fileConfig{}) {
		t.Fatalf("empty file: %+v, %v", cfg, err)
	}
}

// capture returns deps whose run stores the options it was called with and plays the given events.
func capture(d deps, got *client.Options, events ...client.Event) deps {
	d.run = func(_ context.Context, o client.Options) error {
		*got = o
		for _, e := range events {
			o.OnEvent(e)
		}
		return nil
	}
	return d
}

func writeConfig(t *testing.T, server, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := saveConfig(path, fileConfig{Server: server, Token: token}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCredentialPrecedence(t *testing.T) {
	fileTok, envTok, flagTok := testToken(t), testToken(t), testToken(t)
	path := writeConfig(t, "https://file.example.com", fileTok)

	var got client.Options
	run := func(env map[string]string, extra ...string) error {
		d := capture(testDeps(env), &got)
		_, _, err := execute(t, d, append([]string{"--config", path, "http", "8080"}, extra...)...)
		return err
	}

	if err := run(nil); err != nil || got.ServerURL != "https://file.example.com" || got.Token != fileTok {
		t.Fatalf("file: %v %+v", err, got)
	}
	env := map[string]string{envServer: "https://env.example.com", envToken: envTok}
	if err := run(env); err != nil || got.ServerURL != "https://env.example.com" || got.Token != envTok {
		t.Fatalf("env: %v %+v", err, got)
	}
	err := run(env, "--server", "https://flag.example.com", "--token", flagTok)
	if err != nil || got.ServerURL != "https://flag.example.com" || got.Token != flagTok {
		t.Fatalf("flag: %v %+v", err, got)
	}
	// mixed: the token from the flag, the server from the environment
	if err := run(env, "--token", flagTok); err != nil || got.ServerURL != "https://env.example.com" || got.Token != flagTok {
		t.Fatalf("mixed: %v %+v", err, got)
	}
}

func TestNoCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "none.yaml")
	called := false
	d := testDeps(nil)
	d.run = func(context.Context, client.Options) error { called = true; return nil }
	_, _, err := execute(t, d, "--config", path, "http", "8080")
	if err == nil || !strings.Contains(err.Error(), "porthole login") || called {
		t.Fatalf("err = %v, run called = %v", err, called)
	}

	bad := writeConfig(t, "https://x.example.com", "garbage")
	_, _, err = execute(t, d, "--config", bad, "http", "8080")
	if err == nil || !strings.Contains(err.Error(), "malformed") || called {
		t.Fatalf("err = %v, run called = %v", err, called)
	}
}

func TestHTTPCommand(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var got client.Options
	d := capture(testDeps(nil), &got,
		client.Connected{ClientName: "home"},
		client.TunnelReady{
			Spec:      client.TunnelSpec{Kind: proto.KindHTTP, Name: "http-8080", LocalAddr: "127.0.0.1:8080"},
			Name:      "http-8080",
			PublicURL: "https://http-8080-home.tun.example.com",
		},
		client.Disconnected{Err: errors.New("boom"), RetryIn: 2300 * time.Millisecond},
		client.TunnelClosed{Name: "x", Reason: "quota"},
	)
	stdout, stderr, err := execute(t, d, "--config", path, "http", "8080", "--name", "blog")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 1 || got.Tunnels[0] != (client.TunnelSpec{Kind: "http", Name: "blog", LocalAddr: "127.0.0.1:8080"}) {
		t.Fatalf("tunnels %+v", got.Tunnels)
	}
	if got.Version != "1.2.3" || got.Logger == nil {
		t.Fatalf("options %+v", got)
	}
	if !strings.Contains(stdout, "https://http-8080-home.tun.example.com -> 127.0.0.1:8080") ||
		!strings.Contains(stdout, "connected as home") {
		t.Errorf("stdout %q", stdout)
	}
	if !strings.Contains(stderr, "reconnecting in 3s: boom") || !strings.Contains(stderr, "tunnel x closed: quota") {
		t.Errorf("stderr %q", stderr)
	}
}

func TestTCPCommand(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var got client.Options
	d := capture(testDeps(nil), &got, client.TunnelReady{
		Spec:      client.TunnelSpec{Kind: proto.KindTCP, Name: "tcp-7575", LocalAddr: "nas:7575"},
		Name:      "tcp-7575",
		PublicURL: "tcp://tun.example.com:20017",
	})
	stdout, _, err := execute(t, d, "--config", path, "tcp", "nas:7575", "--remote-port", "20017")
	if err != nil {
		t.Fatal(err)
	}
	want := client.TunnelSpec{Kind: "tcp", LocalAddr: "nas:7575", RemotePort: 20017}
	if got.Tunnels[0] != want {
		t.Fatalf("tunnels %+v, want %+v", got.Tunnels, want)
	}
	if !strings.Contains(stdout, "tcp://tun.example.com:20017 -> nas:7575") || strings.Contains(stdout, "ssh -p") {
		t.Errorf("stdout %q", stdout)
	}
	if _, _, err := execute(t, d, "--config", path, "tcp", "5432", "--remote-port", "99999"); err == nil {
		t.Error("an out-of-range --remote-port must be rejected")
	}
}

func TestSSHCommand(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var got client.Options
	ready := client.TunnelReady{
		Spec:      client.TunnelSpec{Kind: proto.KindTCP, Name: "ssh", LocalAddr: "127.0.0.1:22"},
		Name:      "ssh",
		PublicURL: "tcp://tun.example.com:20018",
	}
	d := capture(testDeps(nil), &got, ready)

	stdout, _, err := execute(t, d, "--config", path, "ssh", "--public-port")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tunnels[0] != (client.TunnelSpec{Kind: "tcp", Name: "ssh", LocalAddr: "127.0.0.1:22"}) {
		t.Fatalf("tunnels %+v", got.Tunnels)
	}
	if !strings.Contains(stdout, "ssh -p 20018 alice@tun.example.com") {
		t.Errorf("stdout %q", stdout)
	}

	stdout, _, err = execute(t, d, "--config", path, "ssh", "--public-port", "--user", "bob", "--local-port", "2222", "--name", "box")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tunnels[0] != (client.TunnelSpec{Kind: "tcp", Name: "box", LocalAddr: "127.0.0.1:2222"}) ||
		!strings.Contains(stdout, "ssh -p 20018 bob@tun.example.com") {
		t.Errorf("tunnels %+v, stdout %q", got.Tunnels, stdout)
	}
}

func TestFatalErrorsAreExplained(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	cases := map[string]string{
		proto.CodeUnauthorized:       "token rejected by server; run `porthole login`",
		proto.CodeTokenRevoked:       "run `porthole login`",
		proto.CodeNameTaken:          "--name",
		proto.CodeUnsupportedVersion: "upgrade porthole",
	}
	for code, want := range cases {
		d := testDeps(nil)
		perr := &proto.Error{Code: code, Message: "details"}
		d.run = func(context.Context, client.Options) error { return perr }
		_, _, err := execute(t, d, "--config", path, "http", "8080")
		if err == nil || !strings.Contains(err.Error(), strings.Split(want, ";")[0]) {
			t.Errorf("%s: error %v does not contain %q", code, err, want)
			continue
		}
		var got *proto.Error
		if !errors.As(err, &got) || got != perr {
			t.Errorf("%s: the original error is not reachable through errors.As", code)
		}
	}
	d := testDeps(nil)
	d.run = func(context.Context, client.Options) error { return errors.New("plain") }
	if _, _, err := execute(t, d, "--config", path, "http", "8080"); err == nil || err.Error() != "plain" {
		t.Errorf("plain errors must pass through, got %v", err)
	}
}

func TestVersionCommand(t *testing.T) {
	stdout, _, err := execute(t, testDeps(nil), "version")
	if err != nil || !strings.HasPrefix(stdout, "porthole 1.2.3 (") {
		t.Fatalf("%q, %v", stdout, err)
	}
}

func TestSSHCommandLine(t *testing.T) {
	if got, ok := sshCommand("tcp://tun.example.com:20018", "me"); !ok || got != "ssh -p 20018 me@tun.example.com" {
		t.Errorf("got %q, %v", got, ok)
	}
	if _, ok := sshCommand("https://tun.example.com", "me"); ok {
		t.Error("a URL without a port has no ssh command")
	}
}
