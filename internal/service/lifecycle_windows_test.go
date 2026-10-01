// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestWindowsServiceLifecycle installs a real service built from testdata/svcstub. It changes the machine, so it
// needs PORTHOLE_TEST_SERVICE=1 and an elevated terminal.
func TestWindowsServiceLifecycle(t *testing.T) {
	if os.Getenv("PORTHOLE_TEST_SERVICE") != "1" {
		t.Skip("set PORTHOLE_TEST_SERVICE=1 to install a real Windows service")
	}
	if !Elevated() {
		t.Skip("needs an elevated terminal")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "svcstub.exe")
	if out, err := exec.Command("go", "build", "-o", exe, "./testdata/svcstub").CombinedOutput(); err != nil {
		t.Fatalf("build the stub: %v\n%s", err, out)
	}
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatal(err)
	}
	name := "porthole-test-" + hex.EncodeToString(rnd[:])
	marker := filepath.Join(dir, "marker.txt")

	m, err := New(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Uninstall(name) })

	if err := m.Install(Spec{Name: name, Exe: exe, Args: []string{"--name", name, "--marker", marker}}); err != nil {
		t.Fatal(err)
	}
	st, err := m.Status(name)
	if err != nil || !st.Installed || !st.Running || st.PID == 0 {
		t.Fatalf("Status after Install = %+v, %v; want a running service", st, err)
	}

	if out, err := exec.Command("sc.exe", "control", name, "paramchange").CombinedOutput(); err != nil {
		t.Fatalf("sc control paramchange: %v\n%s", err, out)
	}
	waitFor(t, "the reload marker", func() bool {
		data, _ := os.ReadFile(marker)
		return strings.Contains(string(data), "reload")
	})

	if err := m.Stop(name); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(name); st.Running {
		t.Errorf("Status after Stop = %+v", st)
	}
	if err := m.Start(name); err != nil {
		t.Fatal(err)
	}
	if err := m.Restart(name); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(name); !st.Running {
		t.Errorf("Status after Restart = %+v", st)
	}
	// Re-running Install updates the definition and keeps the service running.
	if err := m.Install(Spec{Name: name, Exe: exe, Args: []string{"--name", name, "--marker", marker}}); err != nil {
		t.Fatalf("second Install: %v", err)
	}

	if err := m.Uninstall(name); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the service to disappear", func() bool {
		c, err := connect(windows.SC_MANAGER_CONNECT)
		if err != nil {
			return false
		}
		defer func() { _ = c.Disconnect() }()
		s, err := openService(c, name, windows.SERVICE_QUERY_STATUS)
		if err == nil {
			s.Close()
			return false
		}
		return errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST)
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
