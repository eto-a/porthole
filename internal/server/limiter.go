// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"math"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter surfaces. Each has its own failure buckets, so that noise on one (an unauthenticated join endpoint, a
// scanner on the SSH gateway) cannot lock a client out of another. Behind a proxy without PROXY protocol or
// trusted X-Forwarded-For every visitor shares the proxy's address; separate surfaces keep that from turning one
// bad actor on the cheapest surface into an outage of all of them.
const (
	surfaceHandshake = iota // control handshakes of clients
	surfaceAdmin            // admin API and MCP bearer authentication
	surfaceJoin             // join code redemption
	surfaceSSH              // SSH gateway password authentication
	numSurfaces
)

const (
	failRate        = rate.Limit(5.0 / 60.0) // sustained failures per second per source (5 per minute)
	failBurst       = 10
	limiterSweepGap = time.Minute
	limiterMaxKeys  = 1 << 16 // per surface
	evictSample     = 8       // entries examined when the table is full
)

// failLimiter rate-limits failed authentication attempts per source and surface. Only failures consume tokens, so
// a well-behaved client is never slowed down.
//
// Sources are IPv4 addresses and IPv6 /64 prefixes (one customer holds a whole /64, so per-address buckets would
// be unlimited for them). When a surface table is full the limiter does not fail open and does not refuse
// unknown sources (which would let an attacker lock everybody else out): it evicts the entry with the most
// recovered budget among a random sample, so a new source is always tracked and the attacker's own address, with
// its spent budget, is the last to go.
type failLimiter struct {
	mu        sync.Mutex
	m         [numSurfaces]map[string]*rate.Limiter
	maxKeys   int
	lastSweep time.Time
}

func newFailLimiter() *failLimiter {
	f := &failLimiter{maxKeys: limiterMaxKeys}
	for i := range f.m {
		f.m[i] = make(map[string]*rate.Limiter)
	}
	return f
}

// limiterKey maps an IP string to its bucket key: the address itself for IPv4 (and 4-in-6), the /64 prefix for
// IPv6. Anything that does not parse is used as is.
func limiterKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

// blocked reports whether ip has exhausted its failure budget on surface at now, and how long to wait.
func (f *failLimiter) blocked(surface int, ip string, now time.Time) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(now)
	lim, ok := f.m[surface][limiterKey(ip)]
	if !ok {
		return 0, false
	}
	tokens := lim.TokensAt(now)
	if tokens >= 1 {
		return 0, false
	}
	wait := time.Duration(math.Ceil((1-tokens)/float64(failRate))) * time.Second
	return wait, true
}

// fail records one failed attempt from ip on surface.
func (f *failLimiter) fail(surface int, ip string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(now)
	tbl, key := f.m[surface], limiterKey(ip)
	lim, ok := tbl[key]
	if !ok {
		if len(tbl) >= f.maxKeys {
			f.evictLocked(tbl, now)
		}
		lim = rate.NewLimiter(failRate, failBurst)
		tbl[key] = lim
	}
	lim.AllowN(now, 1)
}

// evictLocked drops the entry with the most recovered budget among a few arbitrary ones (Go's map iteration order
// is randomised).
func (f *failLimiter) evictLocked(tbl map[string]*rate.Limiter, now time.Time) {
	var victim string
	best := -1.0
	n := 0
	for k, lim := range tbl {
		if t := lim.TokensAt(now); t > best {
			victim, best = k, t
		}
		if n++; n >= evictSample {
			break
		}
	}
	delete(tbl, victim)
}

// size returns the number of tracked sources over all surfaces.
func (f *failLimiter) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, t := range f.m {
		n += len(t)
	}
	return n
}

// sweepLocked drops entries whose budget has fully recovered.
func (f *failLimiter) sweepLocked(now time.Time) {
	if now.Sub(f.lastSweep) < limiterSweepGap {
		return
	}
	f.lastSweep = now
	for _, tbl := range f.m {
		for k, lim := range tbl {
			if lim.TokensAt(now) >= failBurst {
				delete(tbl, k)
			}
		}
	}
}
