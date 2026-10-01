// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/localapi"
)

// TestRemoteOpenThroughTheAdminSocket runs `portholed admin open` against a server whose client is the daemon: the
// daemon opens the tunnel on request, and the tunnel answers. A target outside allow_remote is refused.
func TestRemoteOpenThroughTheAdminSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the admin socket is a unix socket")
	}
	skipUnlessCurrentClient(t)
	if os.Getenv(envServerBin) != "" {
		t.Skip("remote open needs the portholed of the working tree")
	}
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	e, tok := setup(t, fmt.Sprintf("admin_socket: %q\n", sock))
	httpPort, _ := backend(t)

	// Only the backend port may be exposed on request.
	d := startDaemon(t, e, tok, fmt.Sprintf("version: 1\nallow_remote: [%d]\n", httpPort))

	admin := func(args ...string) (string, error) {
		return output(portholed, append([]string{"admin", "open", "-c", e.cfgPath, "--socket", sock}, args...)...)
	}

	out, err := admin("home", "http", fmt.Sprint(httpPort), "--name", "remote", "--json")
	if err != nil {
		t.Fatalf("admin open: %v\n%s", err, out)
	}
	var res struct {
		Client string `json:"client"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		URL    string `json:"public_url"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Client != "home" || res.Name != "remote" || res.URL == "" {
		t.Fatalf("output %q: %v", out, err)
	}
	e.mustServe(t, "remote-home")
	if tn, ok := d.tunnel("remote"); !ok || tn.Source != localapi.SourceRuntime {
		t.Errorf("the daemon does not list the remote tunnel as a runtime tunnel: %+v, %v", tn, ok)
	}

	// Outside allow_remote: refused by the machine, whatever the server says.
	out, err = admin("home", "http", fmt.Sprint(httpPort+1), "--name", "nope")
	if err == nil || !strings.Contains(out, "not_allowed") {
		t.Errorf("refused target: err=%v\n%s", err, out)
	}

	// Closed like any runtime tunnel.
	d.mustCLI("close", "remote")
	d.waitGone("remote")
}

// TestRemoteOpenDefaultsToThisMachine: a daemon without allow_remote exposes loopback targets on request, and refuses
// a LAN address and a link-local one (cloud metadata) with not_allowed.
func TestRemoteOpenDefaultsToThisMachine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the admin socket is a unix socket")
	}
	skipUnlessCurrentClient(t)
	if os.Getenv(envServerBin) != "" {
		t.Skip("remote open needs the portholed of the working tree")
	}
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	e, tok := setup(t, fmt.Sprintf("admin_socket: %q\n", sock))
	httpPort, _ := backend(t)
	d := startDaemon(t, e, tok, "version: 1\n")

	admin := func(args ...string) (string, error) {
		return output(portholed, append([]string{"admin", "open", "-c", e.cfgPath, "--socket", sock}, args...)...)
	}
	if out, err := admin("home", "http", fmt.Sprint(httpPort), "--name", "local"); err != nil {
		t.Fatalf("loopback target: %v\n%s", err, out)
	}
	e.mustServe(t, "local-home")
	for _, target := range []string{"192.168.1.1:80", "169.254.169.254:80"} {
		out, err := admin("home", "tcp", target, "--name", "lan")
		if err == nil || !strings.Contains(out, "not_allowed") {
			t.Errorf("%s: err=%v\n%s", target, err, out)
		}
	}
	d.mustCLI("close", "local")
	d.waitGone("local")
}
