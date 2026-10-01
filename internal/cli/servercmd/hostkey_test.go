// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/server"
)

func runHostKey(t *testing.T, cfg *config.Config, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "portholed", SilenceUsage: true, SilenceErrors: true}
	jsonout.AddFlag(root)
	root.AddCommand(NewHostKey(func() (*config.Config, error) { return cfg, nil }))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs(append([]string{"ssh-hostkey"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestHostKeyJSON(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, server.HostKeyFile), pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = dir

	text, err := runHostKey(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runHostKey(t, cfg, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Fingerprint string `json:"fingerprint"`
		Path        string `json:"path"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if !strings.HasPrefix(doc.Fingerprint, "SHA256:") || doc.Fingerprint != strings.TrimSpace(text) ||
		doc.Path != filepath.Join(dir, server.HostKeyFile) {
		t.Errorf("json %+v, text %q", doc, text)
	}
}
