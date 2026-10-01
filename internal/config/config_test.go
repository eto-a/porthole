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

func TestTraffic(t *testing.T) {
	const base = "version: 1\ndomain: a.example\ndata_dir: /tmp/x\n"
	c, err := Load(write(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Traffic.MaxRequests != 10000 || c.Traffic.MaxConns != 10000 {
		t.Fatalf("default traffic: %+v", c.Traffic)
	}
	c, err = Load(write(t, base+"traffic:\n  max_requests: 0\n  max_conns: 50\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Traffic.MaxRequests != 0 || c.Traffic.MaxConns != 50 {
		t.Fatalf("file traffic: %+v", c.Traffic)
	}
	t.Setenv("PORTHOLED_TRAFFIC_MAX_REQUESTS", "7")
	t.Setenv("PORTHOLED_TRAFFIC_MAX_CONNS", "0")
	c, err = Load(write(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Traffic.MaxRequests != 7 || c.Traffic.MaxConns != 0 {
		t.Fatalf("env traffic: %+v", c.Traffic)
	}
	t.Setenv("PORTHOLED_TRAFFIC_MAX_REQUESTS", "-1")
	if _, err := Load(write(t, base)); err == nil || !strings.Contains(err.Error(), "traffic.max_requests") {
		t.Fatalf("negative max_requests: %v", err)
	}
	t.Setenv("PORTHOLED_TRAFFIC_MAX_REQUESTS", "1")
	t.Setenv("PORTHOLED_TRAFFIC_MAX_CONNS", "-1")
	if _, err := Load(write(t, base)); err == nil || !strings.Contains(err.Error(), "traffic.max_conns") {
		t.Fatalf("negative max_conns: %v", err)
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
		"no domain":            "version: 1\n",
		"bad version":          "version: 2\ndomain: a.example\n",
		"url as domain":        "version: 1\ndomain: https://a.example\n",
		"half tls":             "version: 1\ndomain: a.example\ntls:\n  cert_file: c.pem\n",
		"bad range":            "version: 1\ndomain: a.example\ntcp_port_range: 3000-2000\n",
		"bad listen":           "version: 1\ndomain: a.example\nlisten: '443'\n",
		"bad scheme":           "version: 1\ndomain: a.example\npublic_scheme: ftp\n",
		"server_url no scheme": "version: 1\ndomain: a.example\nserver_url: tun.example.com\n",
		"server_url ftp":       "version: 1\ndomain: a.example\nserver_url: ftp://tun.example.com\n",
		"server_url path":      "version: 1\ndomain: a.example\nserver_url: https://tun.example.com/x\n",
		"server_url query":     "version: 1\ndomain: a.example\nserver_url: https://tun.example.com?a=b\n",
		"server_url no host":   "version: 1\ndomain: a.example\nserver_url: https://\n",
		"zero max tunls":       "version: 1\ndomain: a.example\nmax_tunnels_per_client: 0\n",
		"ssh no port":          "version: 1\ndomain: a.example\nssh_gateway:\n  listen: '2222'\n",
		"ssh named port":       "version: 1\ndomain: a.example\nssh_gateway:\n  listen: ':ssh'\n",
		"ssh negative":         "version: 1\ndomain: a.example\nssh_gateway:\n  max_conns_per_tunnel: -1\n",
		"bad tls mode":         "version: 1\ndomain: a.example\ntls:\n  mode: auto\n",
		"files no certs":       "version: 1\ndomain: a.example\ntls:\n  mode: files\n",
		"acme with certs":      "version: 1\ndomain: a.example\ntls:\n  mode: acme\n  cert_file: c.pem\n  key_file: k.pem\n",
		"off with certs":       "version: 1\ndomain: a.example\ntls:\n  mode: off\n  cert_file: c.pem\n  key_file: k.pem\n",
		"acme in files":        "version: 1\ndomain: a.example\ntls:\n  cert_file: c.pem\n  key_file: k.pem\n  acme:\n    email: a@b.example\n",
		"acme in off":          "version: 1\ndomain: a.example\ntls:\n  mode: off\n  acme:\n    ca: https://ca.example/dir\n",
		"bad acme ca":          "version: 1\ndomain: a.example\ntls:\n  acme:\n    ca: not-a-url\n",
		"http listen off":      "version: 1\ndomain: a.example\nhttp_listen: ':80'\ntls:\n  mode: off\n",
		"bad http listen":      "version: 1\ndomain: a.example\nhttp_listen: '80'\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestServerURL(t *testing.T) {
	c, err := Load(write(t, "version: 1\ndomain: a.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerURL != "" || c.ClientURL() != "" {
		t.Fatalf("default: ServerURL %q ClientURL %q, want empty", c.ServerURL, c.ClientURL())
	}
	for in, want := range map[string]string{
		"https://tun.example.com":      "https://tun.example.com",
		"https://tun.example.com/":     "https://tun.example.com",
		"http://localhost:8080":        "http://localhost:8080",
		"https://tun.example.com:8443": "https://tun.example.com:8443",
	} {
		c, err := Load(write(t, "version: 1\ndomain: a.example\nserver_url: "+in+"\n"))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := c.ClientURL(); got != want {
			t.Errorf("%s: ClientURL = %q, want %q", in, got, want)
		}
	}
	t.Setenv("PORTHOLED_SERVER_URL", "https://env.example/")
	c, err = Load(write(t, "version: 1\ndomain: a.example\nserver_url: https://file.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientURL() != "https://env.example" {
		t.Fatalf("env not applied: %q", c.ClientURL())
	}
}

func TestAdminSocketPath(t *testing.T) {
	c, err := Load(write(t, "version: 1\ndomain: tun.example.com\ndata_dir: /srv/ph\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.AdminSocketPath(), filepath.Join(c.DataDir, "admin.sock"); got != want {
		t.Errorf("default %q, want %q", got, want)
	}
	c.AdminSocket = "/run/ph.sock"
	if got := c.AdminSocketPath(); got != "/run/ph.sock" {
		t.Errorf("explicit %q", got)
	}
	c.AdminSocket = "-"
	if got := c.AdminSocketPath(); got != "" {
		t.Errorf("off %q, want empty", got)
	}
	t.Setenv("PORTHOLED_ADMIN_SOCKET", "-")
	c, err = Load(write(t, "version: 1\ndomain: tun.example.com\ndata_dir: /srv/ph\n"))
	if err != nil || c.AdminSocketPath() != "" {
		t.Errorf("env override: %q, %v", c.AdminSocketPath(), err)
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

func TestTLSModeDefaults(t *testing.T) {
	tests := []struct {
		name, body, mode, httpListen string
		tlsEnabled                   bool
	}{
		{"no tls section is acme", "", "acme", ":80", true},
		{"cert files imply files", "tls:\n  cert_file: c.pem\n  key_file: k.pem\n", "files", "", true},
		{"explicit files", "tls:\n  mode: files\n  cert_file: c.pem\n  key_file: k.pem\n", "files", "", true},
		{"explicit off", "tls:\n  mode: off\n", "off", "", false},
		{"acme with options", "tls:\n  mode: acme\n  acme:\n    email: a@b.example\n    ca: https://ca.example/dir\n", "acme", ":80", true},
		{"http_listen override", "http_listen: ':8080'\n", "acme", ":8080", true},
		{"http_listen disabled", "http_listen: ''\n", "acme", "", true},
		{"http_listen with files", "http_listen: ':80'\ntls:\n  cert_file: c.pem\n  key_file: k.pem\n", "files", ":80", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(write(t, "version: 1\ndomain: a.example\ndata_dir: /tmp/x\n"+tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if got := c.TLS.EffectiveMode(); got != tc.mode {
				t.Errorf("mode %q, want %q", got, tc.mode)
			}
			if got := c.HTTPListenAddr(); got != tc.httpListen {
				t.Errorf("http listen %q, want %q", got, tc.httpListen)
			}
			if got := c.TLS.Enabled(); got != tc.tlsEnabled {
				t.Errorf("Enabled %v, want %v", got, tc.tlsEnabled)
			}
		})
	}
}

func TestACMEDefaults(t *testing.T) {
	c, err := Load(write(t, "version: 1\ndomain: a.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.TLS.ACME.CAURL(); got != DefaultACMECA {
		t.Errorf("default CA %q", got)
	}
	c, err = Load(write(t, "version: 1\ndomain: a.example\ntls:\n  acme:\n    ca: https://ca.example/dir\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.TLS.ACME.CAURL(); got != "https://ca.example/dir" {
		t.Errorf("custom CA %q", got)
	}
}

func TestTLSEnv(t *testing.T) {
	t.Setenv("PORTHOLED_TLS_MODE", "acme")
	t.Setenv("PORTHOLED_ACME_EMAIL", "ops@a.example")
	t.Setenv("PORTHOLED_ACME_CA", "https://acme-staging-v02.api.letsencrypt.org/directory")
	t.Setenv("PORTHOLED_HTTP_LISTEN", ":8080")
	c, err := Load(write(t, "version: 1\ndomain: a.example\ntls:\n  mode: off\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.TLS.Mode != "acme" || c.TLS.ACME.Email != "ops@a.example" || !strings.Contains(c.TLS.ACME.CA, "staging") || c.HTTPListenAddr() != ":8080" {
		t.Fatalf("env not applied: %+v http=%q", c.TLS, c.HTTPListenAddr())
	}
	// An explicitly empty PORTHOLED_HTTP_LISTEN disables the listener.
	t.Setenv("PORTHOLED_HTTP_LISTEN", "")
	c, err = Load(write(t, "version: 1\ndomain: a.example\ntls:\n  mode: acme\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPListenAddr() != "" {
		t.Fatalf("empty env should disable the http listener, got %q", c.HTTPListenAddr())
	}
}

func TestTrafficInspectSettings(t *testing.T) {
	base := "version: 1\ndomain: a.example\ndata_dir: /tmp/x\n"
	c, err := Load(write(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Traffic.AllowInspect || c.Traffic.MaxDetailBytes != 64<<20 {
		t.Fatalf("defaults: %+v", c.Traffic)
	}
	c, err = Load(write(t, base+"traffic:\n  allow_inspect: false\n  max_detail_bytes: 1000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Traffic.AllowInspect || c.Traffic.MaxDetailBytes != 1000 {
		t.Fatalf("file: %+v", c.Traffic)
	}
	t.Setenv("PORTHOLED_TRAFFIC_ALLOW_INSPECT", "true")
	t.Setenv("PORTHOLED_TRAFFIC_MAX_DETAIL_BYTES", "5")
	if c, err = Load(write(t, base+"traffic:\n  allow_inspect: false\n")); err != nil || !c.Traffic.AllowInspect || c.Traffic.MaxDetailBytes != 5 {
		t.Fatalf("env: %+v, %v", c, err)
	}
	t.Setenv("PORTHOLED_TRAFFIC_MAX_DETAIL_BYTES", "-1")
	if _, err := Load(write(t, base)); err == nil || !strings.Contains(err.Error(), "traffic.max_detail_bytes") {
		t.Fatalf("negative budget: %v", err)
	}
}
