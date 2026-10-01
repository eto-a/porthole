// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestPlaintextServer(t *testing.T) {
	for url, want := range map[string]bool{
		"https://tun.example.com":   false,
		"http://tun.example.com":    true,
		"http://192.168.1.5:8080":   true,
		"http://127.0.0.1:8080":     false,
		"http://localhost:8080":     false,
		"http://[::1]:8080":         false,
		"http://tun.example.com/x/": true,
		"not a url":                 false,
	} {
		if got := PlaintextServer(url); got != want {
			t.Errorf("PlaintextServer(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestManagerWarnsAboutPlainHTTP(t *testing.T) {
	for url, want := range map[string]bool{
		"http://tun.example.com":  true,
		"https://tun.example.com": false,
		"http://127.0.0.1:1":      false,
	} {
		var buf bytes.Buffer
		_, err := NewManager(Options{ServerURL: url, Token: newToken(t), Logger: slog.New(slog.NewTextHandler(&buf, nil))})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(buf.String(), "plain http"); got != want {
			t.Errorf("%s: warned=%v, want %v (log %q)", url, got, want, buf.String())
		}
	}
}
