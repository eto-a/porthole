// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sync"
	"time"
)

// ipCounter bounds how many things (connections, pending handshakes) one source may hold at the same time, and
// how many all sources together may. Sources are keyed like the failure limiter's (IPv6 by /64). A limit <= 0
// is off.
type ipCounter struct {
	mu    sync.Mutex
	perIP int
	total int
	n     int
	m     map[string]int
}

func newIPCounter(perIP, total int) *ipCounter {
	return &ipCounter{perIP: perIP, total: total, m: make(map[string]int)}
}

// acquire takes one slot for ip. It returns false, taking nothing, when ip or the whole counter is at its limit.
// Every successful acquire must be paired with release.
func (c *ipCounter) acquire(ip string) bool {
	key := limiterKey(ip)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total > 0 && c.n >= c.total {
		return false
	}
	if c.perIP > 0 && c.m[key] >= c.perIP {
		return false
	}
	c.n++
	c.m[key]++
	return true
}

func (c *ipCounter) release(ip string) {
	key := limiterKey(ip)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n--
	if c.m[key]--; c.m[key] <= 0 {
		delete(c.m, key)
	}
}

// limitOrDefault resolves a Limits value: 0 selects def, a negative value turns the limit off (returned as 0).
func limitOrDefault(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	default:
		return v
	}
}

// durationOrDefault resolves a Limits duration: 0 selects def, a negative value turns the limit off (returned as 0).
func durationOrDefault(v, def time.Duration) time.Duration {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	default:
		return v
	}
}
