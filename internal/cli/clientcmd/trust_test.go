// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/service"
)

// recordPathChecks makes the deps refuse the paths in unsafe and records every path that was checked.
func recordPathChecks(s *svcTest, unsafe ...string) *[]string {
	var checked []string
	s.d.checkPath = func(p string) error {
		checked = append(checked, p)
		for _, u := range unsafe {
			if p == u {
				return &service.UnsafePathError{Path: p, Why: "is writable by every user"}
			}
		}
		return nil
	}
	return &checked
}

func TestServiceInstallCopiesAWritableBinary(t *testing.T) {
	s := newSvcTest(t)
	if _, _, err := execute(t, s.d, "login", "--system", testServer, testToken(t)); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "bin", "porthole")
	copyTo := filepath.Join(t.TempDir(), "protected", "porthole")
	s.d.executable = func() (string, error) { return exe, nil }
	checked := recordPathChecks(s, exe)
	var copied []string
	s.d.copyExe = func(src string) (string, error) {
		copied = append(copied, src)
		return copyTo, nil
	}

	out, _, err := execute(t, s.d, "service", "install", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if len(copied) != 1 || copied[0] != exe {
		t.Errorf("copied %q, want [%q]", copied, exe)
	}
	if len(s.m.specs) != 1 || s.m.specs[0].Exe != copyTo {
		t.Errorf("registered specs %+v, want the copy %q", s.m.specs, copyTo)
	}
	if !contains(*checked, copyTo) {
		t.Errorf("the copy was not checked: %q", *checked)
	}
	var res struct {
		Exe           string `json:"exe"`
		ExeCopiedFrom string `json:"exe_copied_from"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Exe != copyTo || res.ExeCopiedFrom != exe {
		t.Errorf("the result does not report the copy: %s (%v)", out, err)
	}

	// The human output says where the binary came from.
	s2 := newSvcTest(t)
	if _, _, err := execute(t, s2.d, "login", "--system", testServer, testToken(t)); err != nil {
		t.Fatal(err)
	}
	s2.d.executable = s.d.executable
	recordPathChecks(s2, exe)
	s2.d.copyExe = s.d.copyExe
	text, _, err := execute(t, s2.d, "service", "install")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "binary:   copied from "+exe+" to "+copyTo) {
		t.Errorf("output lacks the copy line: %s", text)
	}

	// A copy that does not pass the check is refused and nothing is registered.
	s3 := newSvcTest(t)
	if _, _, err := execute(t, s3.d, "login", "--system", testServer, testToken(t)); err != nil {
		t.Fatal(err)
	}
	s3.d.executable = s.d.executable
	recordPathChecks(s3, exe, copyTo)
	s3.d.copyExe = s.d.copyExe
	if _, _, err := execute(t, s3.d, "service", "install"); err == nil || !strings.Contains(err.Error(), copyTo) {
		t.Errorf("an untrusted copy: error %v", err)
	}
	if len(s3.m.specs) != 0 {
		t.Errorf("an untrusted copy was registered: %v", s3.m.specs)
	}
}

func TestServiceInstallAllowUnsafePathKeepsTheBinary(t *testing.T) {
	s := newSvcTest(t)
	if _, _, err := execute(t, s.d, "login", "--system", testServer, testToken(t)); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "bin", "porthole")
	s.d.executable = func() (string, error) { return exe, nil }
	recordPathChecks(s, exe)
	s.d.copyExe = func(string) (string, error) {
		t.Error("the binary was copied although --allow-unsafe-path was given")
		return "", nil
	}

	out, _, err := execute(t, s.d, "service", "install", "--allow-unsafe-path", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.m.specs) != 1 || s.m.specs[0].Exe != exe {
		t.Errorf("specs %+v, want the original %q", s.m.specs, exe)
	}
	if !strings.Contains(out, "warnings") || !strings.Contains(out, "because of --allow-unsafe-path") {
		t.Errorf("no warning: %s", out)
	}
}

func TestServiceInstallWithoutACopierRefusesAWritableBinary(t *testing.T) {
	s := newSvcTest(t)
	if _, _, err := execute(t, s.d, "login", "--system", testServer, testToken(t)); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "bin", "porthole")
	s.d.executable = func() (string, error) { return exe, nil }
	recordPathChecks(s, exe)
	s.d.copyExe = nil

	_, _, err := execute(t, s.d, "service", "install")
	if err == nil || !strings.Contains(err.Error(), "--allow-unsafe-path") {
		t.Fatalf("error %v", err)
	}
	if len(s.m.calls) != 0 {
		t.Errorf("the service manager was called: %v", s.m.calls)
	}
}

func TestServiceInstallChecksExplicitConfigAndTunnels(t *testing.T) {
	s := newSvcTest(t)
	dir := t.TempDir()
	cfg, tun := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "tun.yaml")
	if err := saveConfig(cfg, fileConfig{Server: testServer, Token: testToken(t)}); err != nil {
		t.Fatal(err)
	}
	checked := recordPathChecks(s, tun)
	s.d.copyExe = func(string) (string, error) {
		t.Error("the binary was copied although the tunnels file is refused")
		return "", nil
	}
	_, _, err := execute(t, s.d, "--config", cfg, "service", "install", "--tunnels", tun)
	if err == nil || !strings.Contains(err.Error(), tun) {
		t.Fatalf("a tunnels file that any user may edit: error %v", err)
	}
	if !contains(*checked, cfg) || !contains(*checked, tun) {
		t.Errorf("checked paths = %q, want the config and the tunnels file", *checked)
	}
	if len(s.m.calls) != 0 {
		t.Errorf("the service manager was called: %v", s.m.calls)
	}

	// The per-user service runs as the user: nothing to protect from the user.
	s2 := newSvcTest(t)
	checked = recordPathChecks(s2, "never")
	if _, _, err := execute(t, s2.d, "--config", cfg, "service", "install", "--user", "--tunnels", tun); err != nil {
		t.Fatal(err)
	}
	if len(*checked) != 0 {
		t.Errorf("a per-user install checked %q", *checked)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestServiceLoggerNeedsAVerifiedDirectory(t *testing.T) {
	s := newSvcTest(t)
	var verified []string
	s.d.verifyDir = func(dir string) error {
		verified = append(verified, dir)
		return &service.UnsafePathError{Path: dir, Why: "is owned by a user"}
	}
	var stderr bytes.Buffer
	app := &app{d: s.d}
	l, closeLog := app.serviceLogger(&stderr)
	defer closeLog()
	l.Info("secret line")

	wantDir := filepath.Join(s.d.getenv("ProgramData"), "porthole")
	if len(verified) != 1 || verified[0] != wantDir {
		t.Errorf("verified %q, want %q", verified, wantDir)
	}
	if _, err := os.Stat(serviceLogPath(s.d.getenv)); err == nil {
		t.Error("the log file was created in a directory that failed the check")
	}
	if !strings.Contains(stderr.String(), "is owned by a user") {
		t.Errorf("the reason is not reported: %q", stderr.String())
	}
}

// makeDirLink makes link a link to the directory target without needing a privilege on Windows (a junction).
func makeDirLink(t *testing.T, link, target string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Skipf("cannot make a junction: %v: %s", err, out)
		}
		return
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestRotatingFileDoesNotFollowLinks(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()

	// logs\ is a link to a directory of someone else.
	base := filepath.Join(root, "porthole")
	if err := os.Mkdir(base, 0o750); err != nil {
		t.Fatal(err)
	}
	makeDirLink(t, filepath.Join(base, "logs"), elsewhere)
	if _, err := openRotatingFile(filepath.Join(base, "logs", "porthole.log"), 100); err == nil {
		t.Error("the log was opened through a link")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("a file was created behind the link: %v", entries)
	}

	// porthole\ itself is a link.
	link := filepath.Join(root, "linked")
	makeDirLink(t, link, elsewhere)
	if _, err := openRotatingFile(filepath.Join(link, "logs", "porthole.log"), 100); err == nil {
		t.Error("the log was opened below a linked directory")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("a directory was created behind the link: %v", entries)
	}
}
