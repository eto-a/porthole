// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates the portholed server configuration (DESIGN.md §3.9).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CurrentVersion is the config schema version understood by this build.
const CurrentVersion = 1

// Config is the server configuration.
type Config struct {
	Version int `yaml:"version"`

	// Domain is the base domain. The control endpoint lives at https://<Domain>/..., HTTP tunnels at
	// https://<label>.<Domain>, TCP tunnels at <Domain>:<port>.
	Domain string `yaml:"domain"`

	// Listen is the address of the HTTP(S) listener, e.g. ":443".
	Listen string `yaml:"listen"`

	TLS TLS `yaml:"tls"`

	// PublicScheme is the scheme used in public HTTP tunnel URLs ("https" or "http").
	// Defaults to "https"; set "http" only for local development.
	PublicScheme string `yaml:"public_scheme"`

	// PublicPort is appended to public HTTP URLs when non-zero (e.g. 8080 in development).
	PublicPort int `yaml:"public_port"`

	// TCPPortRange is the inclusive range of public ports for TCP tunnels, "20000-29999".
	TCPPortRange string `yaml:"tcp_port_range"`

	// TCPBindHost is the address TCP tunnel listeners bind to (default all interfaces).
	TCPBindHost string `yaml:"tcp_bind_host"`

	// DataDir holds the SQLite database.
	DataDir string `yaml:"data_dir"`

	// TrustProxyHeaders makes the server take visitor addresses from X-Forwarded-For.
	// Enable only when portholed runs behind a reverse proxy you control.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`

	// MaxTunnelsPerClient applies to tokens without their own limit.
	MaxTunnelsPerClient int `yaml:"max_tunnels_per_client"`

	// ShutdownGrace bounds graceful shutdown.
	ShutdownGrace time.Duration `yaml:"shutdown_grace"`
}

// TLS configures certificates. Empty CertFile/KeyFile means plain HTTP (for use behind a TLS-terminating proxy).
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether the server terminates TLS itself.
func (t TLS) Enabled() bool { return t.CertFile != "" }

// Default returns a configuration with all defaults applied and no domain.
func Default() *Config {
	return &Config{
		Version:             CurrentVersion,
		Listen:              ":443",
		PublicScheme:        "https",
		TCPPortRange:        "20000-29999",
		DataDir:             "/var/lib/porthole",
		MaxTunnelsPerClient: 10,
		ShutdownGrace:       10 * time.Second,
	}
}

// Load reads the YAML file at path (if path is non-empty), applies PORTHOLED_* environment overrides and
// validates the result. Unknown YAML keys are an error.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	if err := c.applyEnv(os.LookupEnv); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyEnv(lookup func(string) (string, bool)) error {
	str := map[string]*string{
		"PORTHOLED_DOMAIN":         &c.Domain,
		"PORTHOLED_LISTEN":         &c.Listen,
		"PORTHOLED_TLS_CERT_FILE":  &c.TLS.CertFile,
		"PORTHOLED_TLS_KEY_FILE":   &c.TLS.KeyFile,
		"PORTHOLED_PUBLIC_SCHEME":  &c.PublicScheme,
		"PORTHOLED_TCP_PORT_RANGE": &c.TCPPortRange,
		"PORTHOLED_TCP_BIND_HOST":  &c.TCPBindHost,
		"PORTHOLED_DATA_DIR":       &c.DataDir,
	}
	for k, p := range str {
		if v, ok := lookup(k); ok {
			*p = v
		}
	}
	ints := map[string]*int{
		"PORTHOLED_PUBLIC_PORT":            &c.PublicPort,
		"PORTHOLED_MAX_TUNNELS_PER_CLIENT": &c.MaxTunnelsPerClient,
	}
	for k, p := range ints {
		if v, ok := lookup(k); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("config: %s: %w", k, err)
			}
			*p = n
		}
	}
	if v, ok := lookup("PORTHOLED_TRUST_PROXY_HEADERS"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: PORTHOLED_TRUST_PROXY_HEADERS: %w", err)
		}
		c.TrustProxyHeaders = b
	}
	return nil
}

// Validate checks the configuration for consistency.
func (c *Config) Validate() error {
	var errs []error
	if c.Version != CurrentVersion {
		errs = append(errs, fmt.Errorf("version: got %d, this build supports %d", c.Version, CurrentVersion))
	}
	if c.Domain == "" {
		errs = append(errs, errors.New("domain: required"))
	} else if strings.ContainsAny(c.Domain, "/: ") || strings.HasPrefix(c.Domain, ".") {
		errs = append(errs, fmt.Errorf("domain: %q is not a bare host name", c.Domain))
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, fmt.Errorf("listen: %w", err))
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		errs = append(errs, errors.New("tls: cert_file and key_file must be set together"))
	}
	if c.PublicScheme != "https" && c.PublicScheme != "http" {
		errs = append(errs, fmt.Errorf("public_scheme: %q, want https or http", c.PublicScheme))
	}
	if c.PublicPort < 0 || c.PublicPort > 65535 {
		errs = append(errs, fmt.Errorf("public_port: %d out of range", c.PublicPort))
	}
	if _, _, err := c.PortRange(); err != nil {
		errs = append(errs, err)
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir: required"))
	}
	if c.MaxTunnelsPerClient <= 0 {
		errs = append(errs, errors.New("max_tunnels_per_client: must be positive"))
	}
	if c.ShutdownGrace < 0 {
		errs = append(errs, errors.New("shutdown_grace: must not be negative"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// PortRange parses TCPPortRange.
func (c *Config) PortRange() (lo, hi int, err error) {
	a, b, ok := strings.Cut(c.TCPPortRange, "-")
	if ok {
		lo, err = strconv.Atoi(strings.TrimSpace(a))
		if err == nil {
			hi, err = strconv.Atoi(strings.TrimSpace(b))
		}
	}
	if !ok || err != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("tcp_port_range: %q, want \"LOW-HIGH\" within 1-65535", c.TCPPortRange)
	}
	return lo, hi, nil
}

// DBPath is the SQLite database location.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "porthole.db") }
