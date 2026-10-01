// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestProxyProtocolConfig(t *testing.T) {
	base := "version: 1\ndomain: tun.example.com\n"
	c, err := Load(write(t, base+"proxy_protocol: true\ntrusted_proxies: [10.0.0.0/8, 172.16.0.5, \"fd00::/8\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.ProxyProtocol || c.ProxyProtocolHTTP || len(c.TrustedProxies) != 3 {
		t.Fatalf("not parsed: %+v", c)
	}
	for name, body := range map[string]string{
		"no trusted proxies":      "proxy_protocol: true\n",
		"bad CIDR":                "trusted_proxies: [10.0.0.0/33]\n",
		"not an address":          "trusted_proxies: [traefik]\n",
		"zone":                    "trusted_proxies: [\"fe80::1%eth0\"]\n",
		"http without the master": "proxy_protocol_http: true\ntrusted_proxies: [10.0.0.0/8]\n",
	} {
		if _, err := Load(write(t, base+body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(write(t, base+"trusted_proxies: [10.0.0.0/8]\n")); err != nil {
		t.Errorf("trusted_proxies alone must be harmless: %v", err)
	}

	t.Setenv("PORTHOLED_PROXY_PROTOCOL", "true")
	t.Setenv("PORTHOLED_PROXY_PROTOCOL_HTTP", "1")
	t.Setenv("PORTHOLED_TRUSTED_PROXIES", " 10.0.0.0/8 , 172.16.0.0/12,,")
	c, err = Load(write(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if !c.ProxyProtocol || !c.ProxyProtocolHTTP || strings.Join(c.TrustedProxies, "|") != "10.0.0.0/8|172.16.0.0/12" {
		t.Fatalf("env not applied: %+v", c)
	}
	t.Setenv("PORTHOLED_PROXY_PROTOCOL", "maybe")
	if _, err := Load(write(t, base)); err == nil {
		t.Fatal("bad bool env accepted")
	}
}
