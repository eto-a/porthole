// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log"
	"log/slog"
	"strings"
)

// httpErrorLog adapts a slog logger to http.Server.ErrorLog. TLS handshake errors come from scanners and from
// clients that give up (bad protocol, unknown SNI, resets) and would flood the log at Warn, so they are logged at
// Debug; everything else the HTTP server reports (handler panics, accept failures) stays at Warn.
func httpErrorLog(l *slog.Logger) *log.Logger {
	return log.New(errorLogWriter{l: l}, "", 0)
}

type errorLogWriter struct{ l *slog.Logger }

func (w errorLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	if strings.Contains(msg, "TLS handshake error") {
		w.l.Debug("http server: TLS handshake error", "detail", msg)
	} else {
		w.l.Warn("http server error", "detail", msg)
	}
	return len(p), nil
}
