// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type sigStub string

func (s sigStub) String() string { return string(s) }
func (sigStub) Signal()          {}

// syncBuffer is a bytes.Buffer safe for use as a slog destination from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestReloadLoop(t *testing.T) {
	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	trigger := make(chan os.Signal)
	called := make(chan struct{})
	reload := func() error {
		called <- struct{}{}
		return errors.New("boom") // the loop must survive a failing reload
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		reloadLoop(ctx, log, trigger, reload)
	}()

	for range 2 {
		trigger <- sigStub("test-signal")
		select {
		case <-called:
		case <-time.After(5 * time.Second):
			t.Fatal("reload was not called")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reloadLoop did not stop with its context")
	}
	if out := logs.String(); !strings.Contains(out, "reloading tls certificate") || !strings.Contains(out, "signal=test-signal") {
		t.Errorf("signal receipt was not logged: %q", out)
	}
}

func TestWatchReloadStop(*testing.T) {
	stop := watchReload(context.Background(), slog.New(slog.DiscardHandler), func() error { return nil })
	stop() // must not block or panic, also on platforms without reload signals
}
