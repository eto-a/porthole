// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/client"
)

// mustToken is testToken for places that have no *testing.T at hand.
func mustToken() string {
	tok, err := auth.Generate()
	if err != nil {
		panic(err)
	}
	return tok.String()
}

func writeTokenFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // WriteFile is subject to the umask
		t.Fatal(err)
	}
	return p
}

func writeRawConfig(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTokenFileIsUsed(t *testing.T) {
	dir := t.TempDir()
	tok := testToken(t)
	writeTokenFile(t, dir, "token", "  "+tok+" \r\n\n", 0o600)
	cfg := writeRawConfig(t, dir, "server: https://tun.example.com\ntoken_file: token\n") // relative to the config file

	var got client.Options
	d := capture(testDeps(nil), &got)
	if _, _, err := execute(t, d, "--config", cfg, "http", "8080"); err != nil {
		t.Fatal(err)
	}
	if got.Token != tok || got.ServerURL != "https://tun.example.com" {
		t.Fatalf("options %+v", got)
	}

	// An absolute path works too (and the working directory plays no role).
	abs := writeTokenFile(t, dir, "abs-token", tok, 0o600)
	cfg = writeRawConfig(t, dir, "server: https://tun.example.com\ntoken_file: "+filepath.ToSlash(abs)+"\n")
	got = client.Options{}
	if _, _, err := execute(t, d, "--config", cfg, "http", "8080"); err != nil || got.Token != tok {
		t.Fatalf("absolute: err = %v, %+v", err, got)
	}
}

func TestTokenAndTokenFileTogetherIsAnError(t *testing.T) {
	dir := t.TempDir()
	writeTokenFile(t, dir, "token", testToken(t), 0o600)
	cfg := writeRawConfig(t, dir, "server: https://tun.example.com\ntoken: "+testToken(t)+"\ntoken_file: token\n")
	ran := false
	d := testDeps(nil)
	d.run = func(context.Context, client.Options) error { ran = true; return nil }
	_, _, err := execute(t, d, "--config", cfg, "http", "8080")
	if err == nil || !strings.Contains(err.Error(), "either token or token_file") || ran {
		t.Fatalf("err = %v, ran = %v", err, ran)
	}
}

func TestTokenFileProblems(t *testing.T) {
	dir := t.TempDir()
	tests := map[string]struct {
		content string
		mode    os.FileMode
		want    string
	}{
		"empty":     {"\n\n", 0o600, "is empty"},
		"two lines": {mustToken() + "\n" + mustToken() + "\n", 0o600, "single line"},
		"malformed": {"not-a-token\n", 0o600, "malformed"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			writeTokenFile(t, dir, "token", tt.content, tt.mode)
			cfg := writeRawConfig(t, dir, "server: https://tun.example.com\ntoken_file: token\n")
			_, _, err := execute(t, testDeps(nil), "--config", cfg, "http", "8080")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}

	cfg := writeRawConfig(t, dir, "server: https://tun.example.com\ntoken_file: nope\n")
	if _, _, err := execute(t, testDeps(nil), "--config", cfg, "http", "8080"); err == nil || !strings.Contains(err.Error(), "token_file") {
		t.Errorf("missing file: err = %v", err)
	}
}

func TestTokenFileMustNotBeAccessibleByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX file modes")
	}
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o777} {
		writeTokenFile(t, dir, "token", mustToken(), mode)
		cfg := writeRawConfig(t, dir, "server: https://tun.example.com\ntoken_file: token\n")
		_, _, err := execute(t, testDeps(nil), "--config", cfg, "http", "8080")
		if err == nil || !strings.Contains(err.Error(), "accessible by group or others") || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %04o: err = %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		writeTokenFile(t, dir, "token", mustToken(), mode)
		cfg := writeRawConfig(t, dir, "server: https://tun.example.com\ntoken_file: token\n")
		if _, _, err := execute(t, capture(testDeps(nil), &client.Options{}), "--config", cfg, "http", "8080"); err != nil {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
}

func TestFlagAndEnvTokenWinOverTokenFile(t *testing.T) {
	dir := t.TempDir()
	// The token file is unreadable on purpose: it must not even be looked at.
	cfg := writeRawConfig(t, dir, "server: https://tun.example.com\ntoken_file: does-not-exist\n")
	flagTok, envTok := testToken(t), testToken(t)

	var got client.Options
	if _, _, err := execute(t, capture(testDeps(nil), &got), "--config", cfg, "http", "8080", "--token", flagTok); err != nil || got.Token != flagTok {
		t.Fatalf("flag: err = %v, %+v", err, got)
	}
	d := capture(testDeps(map[string]string{envToken: envTok}), &got)
	if _, _, err := execute(t, d, "--config", cfg, "http", "8080"); err != nil || got.Token != envTok {
		t.Fatalf("env: err = %v, %+v", err, got)
	}
}

func TestLoginDropsTokenFile(t *testing.T) {
	dir := t.TempDir()
	cfg := writeRawConfig(t, dir, "server: https://old.example.com\ntoken_file: token\n")
	tok := testToken(t)
	if _, _, err := execute(t, testDeps(nil), "--config", cfg, "login", "https://tun.example.com", tok); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(cfg)
	if err != nil || c.Token != tok || c.TokenFile != "" {
		t.Fatalf("config %+v, %v", c, err)
	}
}

func TestLoadConfigRefusesReadableInlineToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	dir := t.TempDir()
	tok := testToken(t)
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // WriteFile is subject to the umask
			t.Fatal(err)
		}
		return p
	}
	withTok := "server: https://tun.example.com\ntoken: " + tok + "\n"

	if _, err := loadConfig(write("a.yaml", withTok, 0o644)); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("0644 with a token: %v, want a refusal that says chmod 600", err)
	} else if strings.Contains(err.Error(), tok) {
		t.Errorf("the error leaks the token: %v", err)
	}
	if _, err := loadConfig(write("b.yaml", withTok, 0o640)); err == nil {
		t.Error("0640 with a token was accepted")
	}
	if c, err := loadConfig(write("c.yaml", withTok, 0o600)); err != nil || c.Token != tok {
		t.Errorf("0600 with a token: %+v, %v", c, err)
	}
	// Without a token in the file the mode does not matter (the server URL is not a secret).
	if _, err := loadConfig(write("d.yaml", "server: https://tun.example.com\ntoken_file: tok\n", 0o644)); err != nil {
		t.Errorf("0644 without a token: %v", err)
	}
}
