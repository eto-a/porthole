// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/proto"
)

// A slow store (a busy disk) must not stall the registry: another session's lookups and registrations go on while
// a client's ports are being released, and every write still reaches the store, in order, before Close returns.
func TestSlowStoreDoesNotBlockRegistry(t *testing.T) {
	const delay = 300 * time.Millisecond
	h := newHarness(t, withGateway)
	a := h.login(h.st.newToken(t, "alpha"))
	b := h.login(h.st.newToken(t, "beta"))
	for _, n := range []string{"one", "two", "three"} {
		a.mustRegister(proto.KindTCP, n, 0)
	}
	b.mustRegister(proto.KindHTTP, "web", 0)

	h.st.delay.Store(int64(delay))
	a.close() // releaseAll: three slow ReleasePort calls

	var worst time.Duration
	deadline := time.Now().Add(2 * delay)
	for time.Now().Before(deadline) {
		start := time.Now()
		h.srv.lookupSSH("nobody")
		worst = max(worst, time.Since(start))
		time.Sleep(10 * time.Millisecond)
	}
	// A registration of the other session is not held up either.
	start := time.Now()
	b.mustRegister(proto.KindTCP, "late", 0)
	reg := time.Since(start)
	if worst > delay/2 || reg > delay {
		t.Errorf("registry blocked by the store: slowest lookup %s, registration %s (store call takes %s)", worst, reg, delay)
	}

	h.st.delay.Store(0)
	b.close()
	if err := h.srv.Close(); err != nil {
		t.Fatal(err)
	}
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	for _, n := range []string{"one", "two", "three"} {
		r := h.st.ports["alpha/"+n]
		if r == nil || r.ReleasedAt.IsZero() || h.st.live["alpha/"+n] {
			t.Errorf("alpha/%s: release not persisted before Close returned: %+v", n, r)
		}
	}
	if r := h.st.ports["beta/late"]; r == nil || r.ReleasedAt.IsZero() {
		t.Errorf("beta/late: %+v", r)
	}
}
