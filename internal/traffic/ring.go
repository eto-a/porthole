// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package traffic keeps the in-memory journal of proxied HTTP requests and tunnel connections (ADR 0005). It
// stores metadata only: no bodies and no Authorization, Cookie or other headers. Everything is bounded by a ring
// buffer and lost on restart.
package traffic

import "sync"

// ring is a fixed-size, thread-safe ring buffer. Entries get consecutive ids starting at 1; the oldest entry is
// overwritten when the buffer is full. A ring of size 0 stores nothing.
type ring[T any] struct {
	mu   sync.RWMutex
	buf  []T
	next int    // index of the slot the next entry goes to
	n    int    // number of valid entries
	seq  uint64 // id of the newest entry, 0 when empty
}

func newRing[T any](size int) *ring[T] {
	return &ring[T]{buf: make([]T, max(size, 0))}
}

// add stores the entry built by mk, which receives the entry's id, and returns that id (0 for a ring of size 0).
func (r *ring[T]) add(mk func(id uint64) T) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return 0
	}
	r.seq++
	r.buf[r.next] = mk(r.seq)
	r.next = (r.next + 1) % len(r.buf)
	r.n = min(r.n+1, len(r.buf))
	return r.seq
}

// collect returns the entries for which keep reports true, newest first, at most limit of them (limit <= 0 means
// all).
func (r *ring[T]) collect(keep func(*T) bool, limit int) []T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []T
	for i := range r.n {
		e := &r.buf[(r.next-1-i+2*len(r.buf))%len(r.buf)]
		if keep != nil && !keep(e) {
			continue
		}
		out = append(out, *e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// get returns the entry with the given id if it is still in the buffer.
func (r *ring[T]) get(id uint64) (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var zero T
	// n is at most len(buf), so both conversions are lossless.
	if id == 0 || id > r.seq || r.seq-id >= uint64(r.n) { //nolint:gosec // see above
		return zero, false
	}
	back := int(r.seq - id) //nolint:gosec // r.seq-id < r.n
	return r.buf[(r.next-1-back+2*len(r.buf))%len(r.buf)], true
}

// len returns the number of stored entries.
func (r *ring[T]) len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.n
}
