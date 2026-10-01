// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientconfig

import (
	"path/filepath"
	"testing"
)

// The packages install deploy/tunnels.example.yaml as /etc/porthole/tunnels.yaml, so a daemon started on a fresh
// install reads it as is: it must load, and it must not publish anything.
func TestExampleFileLoads(t *testing.T) {
	f, err := Load(filepath.Join("..", "..", "deploy", "tunnels.example.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	specs, err := f.Specs()
	if err != nil {
		t.Fatalf("Specs: %v", err)
	}
	if len(specs) != 0 {
		t.Errorf("example enables %d tunnel(s), want none: %+v", len(specs), specs)
	}
}
