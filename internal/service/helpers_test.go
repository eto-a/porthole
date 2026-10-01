// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// golden compares got with testdata/<name> (LF line ends); -update rewrites the file.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if w := strings.ReplaceAll(string(want), "\r\n", "\n"); w != got {
		t.Errorf("%s differs from the golden file (run with -update after checking the change)\n--- got ---\n%s\n--- want ---\n%s", name, got, w)
	}
}

// fakeRunner records the commands and answers them with handle (nil: success without output).
type fakeRunner struct {
	mu     sync.Mutex
	calls  []string
	handle func(cmd string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	f.mu.Unlock()
	if f.handle != nil {
		return f.handle(cmd)
	}
	return nil, nil
}

func (f *fakeRunner) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}
