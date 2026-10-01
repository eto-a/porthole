// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/config"
)

// lockedBuffer is a bytes.Buffer safe for use as a slog destination from several goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestCertReloaderForcedReload checks the SIGHUP path: the files are re-read at once, without waiting for the
// check interval and without a changed modification time.
func TestCertReloaderForcedReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSigned(t, dir)
	var logs lockedBuffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	cr, err := newCertReloader(certFile, keyFile, log, newFakeClock().Now)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := cr.get(nil)

	// New files, the clock has not moved: the periodic path keeps the old certificate, the forced one does not.
	writeSelfSigned(t, dir)
	if got, _ := cr.get(nil); got != first {
		t.Fatal("certificate was reloaded before the check interval elapsed")
	}
	if err := cr.reload("sighup"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	second, _ := cr.get(nil)
	if second == first {
		t.Fatal("forced reload did not pick up the renewed certificate")
	}
	if out := logs.String(); !strings.Contains(out, "tls certificate reloaded") || !strings.Contains(out, "reason=sighup") ||
		!strings.Contains(out, "not_after=") {
		t.Errorf("success was not logged as expected: %q", out)
	}

	// A broken replacement: error is returned and logged, the previous certificate stays.
	if err := os.WriteFile(certFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cr.reload("sighup"); err == nil {
		t.Fatal("reload of a broken certificate returned nil")
	}
	if got, _ := cr.get(nil); got != second {
		t.Error("a broken certificate file replaced the working one")
	}
	if out := logs.String(); !strings.Contains(out, "tls certificate reload failed") {
		t.Errorf("failure was not logged: %q", out)
	}
}

func TestReloadTLSWithoutTLS(t *testing.T) {
	srv, _, _ := standalone(t, nil)
	if err := srv.ReloadTLS(); err == nil {
		t.Error("ReloadTLS without TLS configured returned nil")
	}
}

// TestServerReloadTLS drives Server.ReloadTLS (what portholed calls on SIGHUP) against a running TLS listener
// and checks which certificate a new connection receives.
func TestServerReloadTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSigned(t, dir)
	srv, _, _ := standalone(t, func(c *config.Config) {
		c.TLS = config.TLS{CertFile: certFile, KeyFile: keyFile}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	serial := func() string {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(),
			&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}

	// Serve loads the certificate asynchronously; wait until the reloader is in place.
	waitFor(t, "certificate loaded", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return srv.certs != nil
	})
	before := serial()

	writeSelfSigned(t, dir) // the real clock is far from the one-minute poll: only ReloadTLS can pick this up
	if got := serial(); got != before {
		t.Fatal("renewed certificate was served before any reload")
	}
	if err := srv.ReloadTLS(); err != nil {
		t.Fatalf("ReloadTLS: %v", err)
	}
	if got := serial(); got == before {
		t.Error("ReloadTLS did not switch to the renewed certificate")
	}
}
