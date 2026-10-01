// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
)

// certBudget limits how many host names without a stored certificate the server asks the CA for (TLS mode "acme").
// Every new tunnel host name would otherwise trigger an issuance on its first TLS handshake, and a client that
// registers, visits and unregisters names in a loop would use up the CA's rate limit for the whole domain (Let's
// Encrypt: 50 new certificates per registered domain per week) and block every other tenant. Caddy documents the
// same risk for on_demand_tls and recommends a rate-limited ask endpoint; this is that endpoint's budget.
//
// A name is charged once per hour while it still has no certificate (the handshake can ask again while issuance
// is in progress or is being retried); names that already have a certificate in storage are free. Refused
// issuances failed at the CA count too, as they are charged when requested.
type certBudget struct {
	// exists reports whether storage already holds a certificate for name. Set when the ACME manager starts; nil
	// means "no".
	exists func(ctx context.Context, name string) bool

	maxPerDay    int // all clients together, 0 = unlimited
	maxPerClient int // per client and hour, 0 = unlimited

	mu        sync.Mutex
	day       []time.Time
	perClient map[string][]time.Time
	charged   map[string]time.Time
}

func newCertBudget(a config.ACME) *certBudget {
	return &certBudget{
		maxPerDay:    limitOrDefault(a.MaxNewNamesPerDay, defaultNewNamesPerDay),
		maxPerClient: limitOrDefault(a.MaxNewNamesPerClientPerHour, maxNewNamesPerClientPerHour),
		perClient:    make(map[string][]time.Time),
		charged:      make(map[string]time.Time),
	}
}

// prune drops entries older than window.
func prune(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= window {
		i++
	}
	return ts[i:]
}

// allow charges name (owned by client, "" if unknown) against the budgets, or refuses it.
func (b *certBudget) allow(ctx context.Context, name, client string, now time.Time) error {
	if b.exists != nil && b.exists(ctx, name) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if at, ok := b.charged[name]; ok && now.Sub(at) < time.Hour {
		return nil
	}
	for n, at := range b.charged {
		if now.Sub(at) >= 24*time.Hour {
			delete(b.charged, n)
		}
	}
	b.day = prune(b.day, now, 24*time.Hour)
	if b.maxPerDay > 0 && len(b.day) >= b.maxPerDay {
		return fmt.Errorf("daily budget of %d new certificates is used up", b.maxPerDay)
	}
	var mine []time.Time
	if client != "" {
		mine = prune(b.perClient[client], now, time.Hour)
		b.perClient[client] = mine
		if b.maxPerClient > 0 && len(mine) >= b.maxPerClient {
			return fmt.Errorf("client %q has used its budget of %d new certificates per hour", client, b.maxPerClient)
		}
	}
	b.day = append(b.day, now)
	if client != "" {
		b.perClient[client] = append(mine, now)
	}
	b.charged[name] = now
	if len(b.perClient) > 1024 { // forget clients with nothing recent
		for c, ts := range b.perClient {
			if len(prune(ts, now, time.Hour)) == 0 {
				delete(b.perClient, c)
			}
		}
	}
	return nil
}

// labelClient returns the client that owns label: the live tunnel's, else the one holding it during the offline
// grace period, else "".
func (s *Server) labelClient(label string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.labels[label]; t != nil {
		return t.sess.name
	}
	if h, ok := s.held[addrKey(proto.KindHTTP, label)]; ok {
		client, _, _ := strings.Cut(h.owner, "/")
		return client
	}
	return ""
}

// hasCert reports whether certmagic's storage holds a certificate for name from our issuer.
func (m *acmeManager) hasCert(ctx context.Context, name string) bool {
	key := certmagic.StorageKeys.SiteCert(m.issuer.IssuerKey(), name)
	return m.magic.Storage.Exists(ctx, key)
}
