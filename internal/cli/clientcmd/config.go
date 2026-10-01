// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Environment variables that override the config file; command-line flags override both.
const (
	envServer = "PORTHOLE_SERVER"
	envToken  = "PORTHOLE_TOKEN"
)

const maxConfigSize = 64 << 10

// fileConfig is the content of the client config file.
type fileConfig struct {
	Server string `yaml:"server"`
	Token  string `yaml:"token"`
}

// defaultConfigPath returns <user config dir>/porthole/config.yaml.
func defaultConfigPath(userConfigDir func() (string, error)) (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate the user config directory (%w); use --config to give a path", err)
	}
	return filepath.Join(dir, "porthole", "config.yaml"), nil
}

// loadConfig reads the config file. A missing file is not an error and yields an empty config.
func loadConfig(path string) (fileConfig, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileConfig{}, nil
	}
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if len(data) > maxConfigSize {
		return fileConfig{}, fmt.Errorf("config %s is larger than %d bytes", path, maxConfigSize)
	}
	var c fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return fileConfig{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return c, nil
}

// saveConfig writes the config atomically: the directory gets mode 0700 if it has to be created, the file 0600.
func saveConfig(path string, c fileConfig) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp") // created with mode 0600
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	_ = tmp.Chmod(0o600) // CreateTemp already uses 0600; Windows has no POSIX modes and may refuse
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
