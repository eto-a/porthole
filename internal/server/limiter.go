// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	failRate        = rate.Limit(5.0 / 60.0) // sustained failed handshakes per second per IP (5 per minute)
	failBurst       = 10
	limiterSweepGap = time.Minute
	limiterMaxIPs   = 1 << 16
)

// failLimiter rate-limits failed handshakes per source IP. Only failures consume tokens, so a well-behaved
// client is never slowed down.
type failLimiter struct {
	mu        sync.Mutex
	m         map[string]*rate.Limiter
	lastSweep time.Time
}

func newFailLimiter() *failLimiter {
	return &failLimiter{m: make(map[string]*rate.Limiter)}
}

// blocked reports whether ip has exhausted its failure budget at now, and how long to wait.
func (f *failLimiter) blocked(ip string, now time.Time) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(now)
	lim, ok := f.m[ip]
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

// fail records one failed handshake from ip.
func (f *failLimiter) fail(ip string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(now)
	lim, ok := f.m[ip]
	if !ok {
		if len(f.m) >= limiterMaxIPs {
			return // refuse to grow without bound; this IP goes untracked
		}
		lim = rate.NewLimiter(failRate, failBurst)
		f.m[ip] = lim
	}
	lim.AllowN(now, 1)
}

// sweepLocked drops entries whose budget has fully recovered.
func (f *failLimiter) sweepLocked(now time.Time) {
	if now.Sub(f.lastSweep) < limiterSweepGap {
		return
	}
	f.lastSweep = now
	for ip, lim := range f.m {
		if lim.TokensAt(now) >= failBurst {
			delete(f.m, ip)
		}
	}
}
