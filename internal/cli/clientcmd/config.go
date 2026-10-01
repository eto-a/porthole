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
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Environment variables that override the config file; command-line flags override both.
const (
	envServer = "PORTHOLE_SERVER"
	envToken  = "PORTHOLE_TOKEN"
)

const (
	maxConfigSize    = 64 << 10
	maxTokenFileSize = 4 << 10
)

// fileConfig is the content of the client config file.
type fileConfig struct {
	Server string `yaml:"server"`
	Token  string `yaml:"token"`
	// TokenFile is a file holding the token on one line, as an alternative to Token (setting both is an error). A
	// relative path is relative to the directory of the config file.
	TokenFile string `yaml:"token_file,omitempty"`
}

// resolveToken returns the token the config file provides: Token, or the content of TokenFile. configPath is the
// path of the config file, which relative token_file paths are resolved against.
func (c fileConfig) resolveToken(configPath string) (string, error) {
	switch {
	case c.Token != "" && c.TokenFile != "":
		return "", fmt.Errorf("config %s: set either token or token_file, not both", configPath)
	case c.TokenFile == "":
		return c.Token, nil
	}
	path := c.TokenFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(configPath), path)
	}
	tok, err := readTokenFile(path)
	if err != nil {
		return "", fmt.Errorf("config %s: token_file: %w", configPath, err)
	}
	return tok, nil
}

// readTokenFile reads a token file: one line, surrounding whitespace trimmed. On Unix it refuses a file that is
// readable by group or others (as ssh does for private keys), because the token is a credential.
func readTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is accessible by group or others (mode %04o); run `chmod 600 %s`", path, fi.Mode().Perm(), path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxTokenFileSize {
		return "", fmt.Errorf("%s is larger than %d bytes", path, maxTokenFileSize)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	if strings.ContainsAny(tok, "\r\n") {
		return "", fmt.Errorf("%s must contain the token on a single line", path)
	}
	return tok, nil
}

// defaultConfigPath returns <user config dir>/porthole/config.yaml.
func defaultConfigPath(userConfigDir func() (string, error)) (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate the user config directory (%w); use --config to give a path", err)
	}
	return filepath.Join(dir, "porthole", "config.yaml"), nil
}

// loadConfig reads the config file. A missing file is not an error and yields an empty config. On Unix a file with an
// inline token must not be accessible by group or others.
func loadConfig(path string) (fileConfig, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileConfig{}, nil
	}
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config %s: %w", path, err)
	}
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
	// An inline token is a credential like the content of a token_file: refuse a file that group or others can read.
	if c.Token != "" && runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return fileConfig{}, fmt.Errorf("config %s holds a token but is accessible by group or others (mode %04o); run `chmod 600 %s`",
			path, fi.Mode().Perm(), path)
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
