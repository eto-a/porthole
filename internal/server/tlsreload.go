// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// certCheckInterval bounds how often the certificate files are stat'ed.
const certCheckInterval = time.Minute

// certReloader serves a certificate loaded from files and picks up renewals (certbot replaces the files in
// place) without a restart. A failed reload keeps the previous certificate.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	now               func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	checked time.Time
	certMod time.Time
	keyMod  time.Time
}

func newCertReloader(certFile, keyFile string, log *slog.Logger, now func() time.Time) (*certReloader, error) {
	c := &certReloader{certFile: certFile, keyFile: keyFile, log: log, now: now}
	if err := c.load(); err != nil {
		return nil, err
	}
	c.checked = now()
	return c, nil
}

// load reads the files. It must be called with c.mu held or before c is shared.
func (c *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("server: load tls certificate: %w", err)
	}
	ci, err := os.Stat(c.certFile)
	if err != nil {
		return fmt.Errorf("server: stat tls certificate: %w", err)
	}
	ki, err := os.Stat(c.keyFile)
	if err != nil {
		return fmt.Errorf("server: stat tls key: %w", err)
	}
	c.cert, c.certMod, c.keyMod = &cert, ci.ModTime(), ki.ModTime()
	return nil
}

// get implements tls.Config.GetCertificate.
func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); now.Sub(c.checked) >= certCheckInterval {
		c.checked = now
		ci, cerr := os.Stat(c.certFile)
		ki, kerr := os.Stat(c.keyFile)
		if cerr == nil && kerr == nil && (!ci.ModTime().Equal(c.certMod) || !ki.ModTime().Equal(c.keyMod)) {
			if err := c.load(); err != nil {
				c.log.Warn("tls certificate reload failed, keeping the previous one", "err", err)
			} else {
				c.log.Info("tls certificate reloaded")
			}
		}
	}
	return c.cert, nil
}
