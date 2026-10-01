// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRenderLaunchdPlistGolden(t *testing.T) {
	spec := Spec{
		Name:   "porthole",
		Exe:    "/usr/local/bin/porthole",
		Args:   []string{"daemon", "--config", "/Library/Application Support/porthole/config.yaml", "--tunnels", "/Library/Application Support/porthole/tunnels.yaml", "--socket", "/var/run/porthole/porthole.sock"},
		LogDir: "/Library/Logs/porthole",
	}
	got, err := renderLaunchdPlist(spec)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "launchd_system.golden", string(got))
}

func TestRenderLaunchdPlistEscapesValues(t *testing.T) {
	spec := Spec{
		Name:   "porthole",
		Exe:    "/Applications/R&D <x>/porthole",
		Args:   []string{"daemon", `--name=a"b'c`, "</string><string>injected"},
		LogDir: "/Users/me/Library/Logs/porthole",
	}
	got, err := renderLaunchdPlist(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "<string>injected") {
		t.Fatalf("an argument was spliced into the XML:\n%s", got)
	}
	// The file is well-formed XML and the arguments come back unchanged.
	var plist struct {
		Strings []string `xml:"dict>array>string"`
	}
	if err := xml.Unmarshal(got, &plist); err != nil {
		t.Fatalf("the plist is not well-formed: %v\n%s", err, got)
	}
	if want := append([]string{spec.Exe}, spec.Args...); !slices.Equal(plist.Strings, want) {
		t.Errorf("ProgramArguments = %q, want %q", plist.Strings, want)
	}
}

func newTestLaunchd(t *testing.T, user bool, fr *fakeRunner) *launchdManager {
	t.Helper()
	m := &launchdManager{
		user: user, run: fr, dir: t.TempDir(), logDir: filepath.Join(t.TempDir(), "logs"),
		domain: "system", elevated: func() bool { return true },
	}
	if user {
		m.domain = "gui/501"
	}
	return m
}

const (
	launchdTarget = "system/io.github.eto-a.porthole"
	printRunning  = "io.github.eto-a.porthole = {\n\tactive count = 1\n\tstate = running\n\tprogram = /usr/local/bin/porthole\n\tpid = 777\n\tevent triggers = {\n\t\tstate = active\n\t}\n}\n"
)

func TestLaunchdInstall(t *testing.T) {
	fr := &fakeRunner{handle: func(cmd string) ([]byte, error) {
		if strings.HasPrefix(cmd, "launchctl print") {
			return nil, errors.New("Could not find service")
		}
		return nil, nil
	}}
	m := newTestLaunchd(t, false, fr)
	if err := m.Install(Spec{Exe: "/usr/local/bin/porthole", Args: []string{"daemon"}}); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(m.dir, "io.github.eto-a.porthole.plist")
	want := []string{
		"launchctl print " + launchdTarget,
		"launchctl enable " + launchdTarget,
		"launchctl bootstrap system " + plist,
	}
	if got := fr.got(); !slices.Equal(got, want) {
		t.Errorf("commands:\n got %q\nwant %q", got, want)
	}
	data, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), filepath.ToSlash(m.logDir)+"/porthole.err.log") {
		t.Errorf("the default log directory is not in the plist:\n%s", data)
	}
	if _, err := os.Stat(m.logDir); err != nil {
		t.Errorf("the log directory was not created: %v", err)
	}
}

func TestLaunchdInstallReloadsLoadedJob(t *testing.T) {
	fr := &fakeRunner{handle: func(cmd string) ([]byte, error) {
		if strings.HasPrefix(cmd, "launchctl print") {
			return []byte(printRunning), nil
		}
		return nil, nil
	}}
	m := newTestLaunchd(t, true, fr)
	m.elevated = func() bool { return false } // an agent needs no root
	if err := m.Install(Spec{User: true, Exe: "/usr/local/bin/porthole"}); err != nil {
		t.Fatal(err)
	}
	got := fr.got()
	if got[1] != "launchctl bootout gui/501/io.github.eto-a.porthole" || !strings.HasPrefix(got[len(got)-1], "launchctl bootstrap gui/501 ") {
		t.Errorf("commands: %q", got)
	}
}

func TestLaunchdNeedsRoot(t *testing.T) {
	m := newTestLaunchd(t, false, &fakeRunner{})
	m.elevated = func() bool { return false }
	if err := m.Install(Spec{Exe: "/usr/local/bin/porthole"}); !errors.Is(err, ErrNotElevated) {
		t.Errorf("Install without root = %v", err)
	}
	if err := m.Uninstall(""); !errors.Is(err, ErrNotElevated) {
		t.Errorf("Uninstall without root = %v", err)
	}
}

func TestLaunchdStatus(t *testing.T) {
	printOut := printRunning
	printErr := errors.New("not loaded")
	fr := &fakeRunner{handle: func(string) ([]byte, error) { return []byte(printOut), printErr }}
	m := newTestLaunchd(t, false, fr)

	st, err := m.Status("")
	if err != nil || st.Installed || st.Running {
		t.Fatalf("Status of nothing = %+v, %v", st, err)
	}
	if err := m.Start(""); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("Start of nothing = %v", err)
	}

	if err := os.WriteFile(filepath.Join(m.dir, "io.github.eto-a.porthole.plist"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	printErr = nil
	st, err = m.Status("")
	if err != nil {
		t.Fatal(err)
	}
	// "state = active" inside event triggers must not be taken for the state of the job.
	if want := (State{Installed: true, Running: true, PID: 777, Detail: "state = running"}); st != want {
		t.Errorf("Status = %+v, want %+v", st, want)
	}

	printErr = errors.New("not loaded")
	if st, _ = m.Status(""); !st.Installed || st.Running || st.Detail != "not loaded" {
		t.Errorf("Status of an unloaded job = %+v", st)
	}
}

func TestLaunchdControl(t *testing.T) {
	loaded := true
	fr := &fakeRunner{handle: func(cmd string) ([]byte, error) {
		if strings.HasPrefix(cmd, "launchctl print") && !loaded {
			return nil, errors.New("not loaded")
		}
		return nil, nil
	}}
	m := newTestLaunchd(t, false, fr)
	plist := filepath.Join(m.dir, "io.github.eto-a.porthole.plist")
	if err := os.WriteFile(plist, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	last := func() string { g := fr.got(); return g[len(g)-1] }

	if err := m.Restart(""); err != nil || last() != "launchctl kickstart -k "+launchdTarget {
		t.Errorf("Restart of a loaded job: %v, last %q", err, last())
	}
	if err := m.Start(""); err != nil || last() != "launchctl kickstart "+launchdTarget {
		t.Errorf("Start of a loaded job: %v, last %q", err, last())
	}
	if err := m.Stop(""); err != nil || last() != "launchctl bootout "+launchdTarget {
		t.Errorf("Stop: %v, last %q", err, last())
	}
	loaded = false
	if err := m.Start(""); err != nil || last() != "launchctl bootstrap system "+plist {
		t.Errorf("Start of an unloaded job: %v, last %q", err, last())
	}
	n := len(fr.got())
	if err := m.Stop(""); err != nil || len(fr.got()) != n+1 { // only the print
		t.Errorf("Stop of an unloaded job: %v, %q", err, fr.got()[n:])
	}
	if err := m.Uninstall(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Errorf("the plist is still there: %v", err)
	}
}
