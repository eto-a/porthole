// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "portholed.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMinimal(t *testing.T) {
	c, err := Load(write(t, "version: 1\ndomain: tun.example.com\ndata_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":443" || c.PublicScheme != "https" || c.MaxTunnelsPerClient != 10 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	lo, hi, err := c.PortRange()
	if err != nil || lo != 20000 || hi != 29999 {
		t.Fatalf("port range %d-%d %v", lo, hi, err)
	}
}

func TestSSHGateway(t *testing.T) {
	c, err := Load(write(t, "version: 1\ndomain: a.example\ndata_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.SSHGateway.Enabled() || c.SSHGateway.Port() != 0 || c.SSHGateway.MaxConnsPerTunnel != 256 {
		t.Fatalf("default gateway: %+v", c.SSHGateway)
	}
	c, err = Load(write(t, "version: 1\ndomain: a.example\ndata_dir: /tmp/x\nssh_gateway:\n  listen: ':2222'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.SSHGateway.Enabled() || c.SSHGateway.Port() != 2222 || c.SSHGateway.MaxConnsPerTunnel != 256 {
		t.Fatalf("gateway with only listen set: %+v", c.SSHGateway)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	_, err := Load(write(t, "version: 1\ndomain: a.example\ndomian: typo\n"))
	if err == nil || !strings.Contains(err.Error(), "domian") {
		t.Fatalf("got %v, want unknown-field error", err)
	}
}

func TestValidate(t *testing.T) {
	tests := map[string]string{
		"no domain":      "version: 1\n",
		"bad version":    "version: 2\ndomain: a.example\n",
		"url as domain":  "version: 1\ndomain: https://a.example\n",
		"half tls":       "version: 1\ndomain: a.example\ntls:\n  cert_file: c.pem\n",
		"bad range":      "version: 1\ndomain: a.example\ntcp_port_range: 3000-2000\n",
		"bad listen":     "version: 1\ndomain: a.example\nlisten: '443'\n",
		"bad scheme":     "version: 1\ndomain: a.example\npublic_scheme: ftp\n",
		"zero max tunls": "version: 1\ndomain: a.example\nmax_tunnels_per_client: 0\n",
		"ssh no port":    "version: 1\ndomain: a.example\nssh_gateway:\n  listen: '2222'\n",
		"ssh named port": "version: 1\ndomain: a.example\nssh_gateway:\n  listen: ':ssh'\n",
		"ssh negative":   "version: 1\ndomain: a.example\nssh_gateway:\n  max_conns_per_tunnel: -1\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("PORTHOLED_DOMAIN", "env.example")
	t.Setenv("PORTHOLED_PUBLIC_PORT", "8080")
	t.Setenv("PORTHOLED_TRUST_PROXY_HEADERS", "true")
	c, err := Load(write(t, "version: 1\ndomain: file.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Domain != "env.example" || c.PublicPort != 8080 || !c.TrustProxyHeaders {
		t.Fatalf("env not applied: %+v", c)
	}
	t.Setenv("PORTHOLED_PUBLIC_PORT", "x")
	if _, err := Load(""); err == nil {
		t.Fatal("bad int env accepted")
	}
}
