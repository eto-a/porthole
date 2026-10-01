// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func gatedPair(t *testing.T, budget int64) (client Session, server Gated) {
	t.Helper()
	srvCh := make(chan Gated, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := AcceptWebSocketGated(w, r, &net.TCPAddr{}, budget)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		srvCh <- s
	}))
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialWebSocket(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), DialOptions{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s := <-srvCh
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c, s
}

// An unauthenticated peer that sends more than the budget loses its connection.
func TestGatedBudgetCutsOffFlood(t *testing.T) {
	c, s := gatedPair(t, 32<<10)
	go func() {
		for range 8 { // 8 extra streams of 64 KiB each, nobody accepts them on the server
			st, err := c.Open()
			if err != nil {
				return
			}
			_, _ = st.Write(make([]byte, 64<<10))
		}
	}()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server kept the connection after the peer exceeded its budget")
	}
}

// After Release the budget no longer applies.
func TestGatedReleaseLiftsBudget(t *testing.T) {
	c, s := gatedPair(t, 4<<10)
	s.Release()
	const size = 256 << 10
	go func() {
		st, err := c.Open()
		if err != nil {
			return
		}
		_, _ = st.Write(make([]byte, size))
		_ = st.Close()
	}()
	st, err := s.Accept()
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, st)
	if err != nil || n != size {
		t.Fatalf("read %d bytes, %v; want %d", n, err, size)
	}
}
