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

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// pair starts a test server and returns connected client and server sessions.
func pair(t *testing.T) (client, server Session) {
	t.Helper()
	srvCh := make(chan Session, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := AcceptWebSocket(w, r, &net.TCPAddr{})
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

func TestStreamsBothDirections(t *testing.T) {
	c, s := pair(t)

	// client → server stream
	go func() {
		st, err := c.Open()
		if err != nil {
			t.Errorf("open: %v", err)
			return
		}
		_, _ = st.Write([]byte("ping"))
		_ = st.Close()
	}()
	st, err := s.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(st); string(b) != "ping" {
		t.Fatalf("got %q", b)
	}

	// server → client stream with a payload larger than one yamux window
	payload := strings.Repeat("x", 1<<20)
	go func() {
		st, err := s.Open()
		if err != nil {
			t.Errorf("open: %v", err)
			return
		}
		_, _ = io.WriteString(st, payload)
		_ = st.Close()
	}()
	st, err = c.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(st); len(b) != len(payload) {
		t.Fatalf("got %d bytes, want %d", len(b), len(payload))
	}
}

func TestCloseIsObserved(t *testing.T) {
	c, s := pair(t)
	_ = c.Close()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server did not observe client close")
	}
	if _, err := s.Accept(); err == nil {
		t.Fatal("accept succeeded on closed session")
	}
}

func TestRejectsPlainHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := AcceptWebSocket(w, r, &net.TCPAddr{}); err == nil {
			t.Error("plain request accepted")
		}
	}))
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}
