// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestHTTPErrorLogLevels(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	el := httpErrorLog(l)
	el.Printf("http: TLS handshake error from 203.0.113.9:1234: EOF")
	el.Printf("http: panic serving 203.0.113.9:1234: boom")
	var hs, panicLine string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		switch {
		case strings.Contains(line, "TLS handshake error"):
			hs = line
		case strings.Contains(line, "panic serving"):
			panicLine = line
		}
	}
	if !strings.Contains(hs, "level=DEBUG") {
		t.Errorf("TLS handshake error not at debug: %q", hs)
	}
	if !strings.Contains(panicLine, "level=WARN") {
		t.Errorf("other errors not at warn: %q", panicLine)
	}
}
