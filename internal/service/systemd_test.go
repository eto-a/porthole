// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var systemSpec = Spec{
	Exe: "/usr/local/bin/porthole",
	Args: []string{
		"daemon", "--config", "/etc/porthole/config.yaml", "--tunnels", "/etc/porthole/tunnels.yaml",
		"--socket", "/run/porthole/porthole.sock",
	},
}

func TestRenderSystemdUnitGolden(t *testing.T) {
	spec, err := systemSpec.normalize()
	if err != nil {
		t.Fatal(err)
	}
	got, err := renderSystemdUnit(spec)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "systemd_system.golden", got)

	user := Spec{
		Name: "porthole", User: true, Exe: "/home/me/.local/bin/porthole",
		Args: []string{"daemon", "--config", "/home/me/my configs/config.yaml", "--socket", "/run/user/1000/porthole/porthole.sock"},
	}
	if user, err = user.normalize(); err != nil {
		t.Fatal(err)
	}
	if got, err = renderSystemdUnit(user); err != nil {
		t.Fatal(err)
	}
	golden(t, "systemd_user.golden", got)

	// Without arguments the unit keeps the arguments of deploy/ and only the binary changes.
	bare := Spec{Exe: "/opt/porthole/bin/porthole"}
	if bare, err = bare.normalize(); err != nil {
		t.Fatal(err)
	}
	if got, err = renderSystemdUnit(bare); err != nil {
		t.Fatal(err)
	}
	golden(t, "systemd_system_default_args.golden", got)
}

func TestRenderSystemdUnitHasNoCRLF(t *testing.T) {
	spec, _ := systemSpec.normalize()
	got, err := renderSystemdUnit(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "\r") {
		t.Error("the unit contains a carriage return")
	}
}

func TestQuoteSystemd(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/bin/porthole": "/usr/bin/porthole",
		"a b":               `"a b"`,
		`say "hi"`:          `"say \"hi\""`,
		"100%":              "100%%",
		"$HOME/x":           "$$HOME/x",
		`C:\x y`:            `"C:\\x y"`,
		"":                  `""`,
	} {
		if got := quoteSystemd(in); got != want {
			t.Errorf("quoteSystemd(%q) = %q, want %q", in, got, want)
		}
	}
}

func newTestSystemd(t *testing.T, user bool, fr *fakeRunner) *systemdManager {
	t.Helper()
	return &systemdManager{user: user, run: fr, dir: t.TempDir(), elevated: func() bool { return true }}
}

const showMissing = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\n"

func TestSystemdInstall(t *testing.T) {
	fr := &fakeRunner{handle: func(cmd string) ([]byte, error) {
		switch {
		case cmd == "id -u porthole-client":
			return nil, errors.New("no such user")
		case strings.HasPrefix(cmd, "systemctl show"):
			return []byte(showMissing), nil
		}
		return nil, nil
	}}
	m := newTestSystemd(t, false, fr)
	if err := m.Install(systemSpec); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"id -u porthole-client",
		"useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin porthole-client",
		"systemctl show porthole.service -p LoadState -p ActiveState -p SubState -p MainPID",
		"systemctl daemon-reload",
		"systemctl enable --now porthole.service",
	}
	if got := fr.got(); !slices.Equal(got, want) {
		t.Errorf("commands:\n got %q\nwant %q", got, want)
	}
	data, err := os.ReadFile(filepath.Join(m.dir, "porthole.service"))
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := systemSpec.normalize()
	if wantUnit, _ := renderSystemdUnit(spec); string(data) != wantUnit {
		t.Error("the unit file differs from the rendered unit")
	}
}

func TestSystemdInstallRestartsRunningUnit(t *testing.T) {
	fr := &fakeRunner{handle: func(cmd string) ([]byte, error) {
		if strings.HasPrefix(cmd, "systemctl show") {
			return []byte("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\n"), nil
		}
		return nil, nil // id succeeds: the user exists
	}}
	m := newTestSystemd(t, false, fr)
	if err := m.Install(systemSpec); err != nil {
		t.Fatal(err)
	}
	calls := fr.got()
	if last := calls[len(calls)-1]; last != "systemctl restart porthole.service" {
		t.Errorf("last command = %q, want a restart", last)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "useradd") {
			t.Error("useradd ran although the user exists")
		}
	}
}

func TestSystemdUserInstall(t *testing.T) {
	fr := &fakeRunner{handle: func(cmd string) ([]byte, error) {
		if strings.HasPrefix(cmd, "systemctl --user show") {
			return []byte(showMissing), nil
		}
		return nil, nil
	}}
	m := newTestSystemd(t, true, fr)
	m.elevated = func() bool { return false } // a user service needs no root
	spec := systemSpec
	spec.User = true
	if err := m.Install(spec); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl --user show porthole.service -p LoadState -p ActiveState -p SubState -p MainPID",
		"systemctl --user daemon-reload",
		"systemctl --user enable --now porthole.service",
	}
	if got := fr.got(); !slices.Equal(got, want) {
		t.Errorf("commands:\n got %q\nwant %q", got, want)
	}
}

func TestSystemdNeedsRootAndMatchingSpec(t *testing.T) {
	m := newTestSystemd(t, false, &fakeRunner{})
	m.elevated = func() bool { return false }
	if err := m.Install(systemSpec); !errors.Is(err, ErrNotElevated) {
		t.Errorf("Install without root = %v, want ErrNotElevated", err)
	}
	if err := m.Uninstall("porthole"); !errors.Is(err, ErrNotElevated) {
		t.Errorf("Uninstall without root = %v, want ErrNotElevated", err)
	}
	m.elevated = func() bool { return true }
	spec := systemSpec
	spec.User = true
	if err := m.Install(spec); err == nil {
		t.Error("Install accepted a user spec on the system manager")
	}
	if err := m.Install(Spec{Exe: "relative/porthole"}); err == nil {
		t.Error("Install accepted a relative binary path")
	}
	if err := m.Install(Spec{Name: "Bad Name", Exe: "/usr/bin/porthole"}); err == nil {
		t.Error("Install accepted a bad service name")
	}
}

func TestSystemdStatusAndControl(t *testing.T) {
	out := showMissing
	fr := &fakeRunner{handle: func(cmd string) ([]byte, error) {
		if strings.HasPrefix(cmd, "systemctl show") {
			return []byte(out), nil
		}
		return nil, nil
	}}
	m := newTestSystemd(t, false, fr)

	st, err := m.Status("")
	if err != nil || st.Installed || st.Running {
		t.Fatalf("Status of a missing unit = %+v, %v", st, err)
	}
	if err := m.Start("porthole"); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("Start of a missing unit = %v, want ErrNotInstalled", err)
	}

	out = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\n"
	st, err = m.Status("porthole")
	if err != nil {
		t.Fatal(err)
	}
	if want := (State{Installed: true, Running: true, PID: 4242, Detail: "active (running)"}); st != want {
		t.Errorf("Status = %+v, want %+v", st, want)
	}
	for _, verb := range []string{"start", "stop", "restart"} {
		fr.calls = nil
		var err error
		switch verb {
		case "start":
			err = m.Start("porthole")
		case "stop":
			err = m.Stop("porthole")
		default:
			err = m.Restart("porthole")
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := fr.got(); got[len(got)-1] != "systemctl "+verb+" porthole.service" {
			t.Errorf("%s ran %q", verb, got)
		}
	}
}

func TestSystemdUninstall(t *testing.T) {
	out := "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=1\n"
	fr := &fakeRunner{handle: func(cmd string) ([]byte, error) {
		if strings.HasPrefix(cmd, "systemctl show") {
			return []byte(out), nil
		}
		return nil, nil
	}}
	m := newTestSystemd(t, false, fr)
	path := filepath.Join(m.dir, "porthole.service")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Uninstall("porthole"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the unit file is still there: %v", err)
	}
	got := fr.got()
	if want := []string{"systemctl disable --now porthole.service", "systemctl daemon-reload"}; !slices.Equal(got[1:], want) {
		t.Errorf("commands after show: %q, want %q", got[1:], want)
	}

	out = showMissing
	fr.calls = nil
	if err := m.Uninstall("porthole"); err != nil {
		t.Errorf("Uninstall of a missing unit: %v", err)
	}
	if len(fr.got()) != 1 {
		t.Errorf("a missing unit ran %q", fr.got())
	}
}
