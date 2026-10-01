// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestSCMConfigGolden(t *testing.T) {
	spec, err := Spec{
		Exe:  `C:\Program Files\porthole\porthole.exe`,
		Args: []string{"daemon", "--config", `C:\ProgramData\porthole\config.yaml`, "--tunnels", `C:\ProgramData\porthole\tunnels.yaml`, "--allow", "porthole-users"},
	}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "scm_config.golden", buildSCMConfig(spec).String())
}

func TestEscapeWindowsArg(t *testing.T) {
	for in, want := range map[string]string{
		"plain":           "plain",
		"":                `""`,
		"a b":             `"a b"`,
		`C:\dir with sp\`: `"C:\dir with sp\\"`,
		`say "hi"`:        `"say \"hi\""`,
		`a\"b`:            `a\\\"b`, // no white space: not wrapped, backslashes before the quote doubled, the quote escaped
	} {
		if got := escapeWindowsArg(in); got != want {
			t.Errorf("escapeWindowsArg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSpecNormalizeRejectsControlCharacters(t *testing.T) {
	if _, err := (Spec{Exe: "/usr/bin/porthole", Args: []string{"a\nb"}}).normalize(); err == nil {
		t.Error("a newline in an argument was accepted")
	}
}

func TestPrepareDarwinDirs(t *testing.T) {
	root := t.TempDir()
	cfg, logs := filepath.Join(root, "Application Support", "porthole"), filepath.Join(root, "Logs", "porthole")
	fr := &fakeRunner{}
	if err := prepareDarwinDirs(context.Background(), fr, cfg, logs); err != nil {
		t.Fatal(err)
	}
	if want := []string{"chown root:admin " + cfg}; !slices.Equal(fr.got(), want) {
		t.Errorf("commands %q, want %q", fr.got(), want)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o750 {
			t.Errorf("mode of the configuration directory = %v, want 0750", fi.Mode().Perm())
		}
	}
	if _, err := os.Stat(logs); err != nil {
		t.Error(err)
	}

	fr = &fakeRunner{handle: func(string) ([]byte, error) { return nil, errors.New("no group admin") }}
	if err := prepareDarwinDirs(context.Background(), fr, cfg, logs); err == nil {
		t.Error("a failing chown was ignored")
	}
}

func TestNewUnsupported(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}
	if _, err := New(true); !errors.Is(err, ErrUnsupported) {
		t.Errorf("New(true) on Windows = %v, want ErrUnsupported", err)
	}
}
