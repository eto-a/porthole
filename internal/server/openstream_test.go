// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/transport"
)

// blockingSession is a transport.Session whose Open blocks until release is closed, like yamux when the peer does
// not accept streams.
type blockingSession struct {
	transport.Session
	release chan struct{}
	done    chan struct{}
	opens   atomic.Int32
	closed  atomic.Int32 // streams handed out by Open and closed by the caller
}

func newBlockingSession() *blockingSession {
	return &blockingSession{release: make(chan struct{}), done: make(chan struct{})}
}

func (b *blockingSession) Open() (net.Conn, error) {
	b.opens.Add(1)
	<-b.release
	c, peer := net.Pipe()
	go func() { _ = peer.Close() }()
	return &countClose{Conn: c, n: &b.closed}, nil
}

func (b *blockingSession) Done() <-chan struct{} { return b.done }

type countClose struct {
	net.Conn
	n *atomic.Int32
}

func (c *countClose) Close() error {
	c.n.Add(1)
	return c.Conn.Close()
}

// A client that does not accept streams must not pin openStream (and the visitor's request) past its context.
func TestOpenStreamHonoursContext(t *testing.T) {
	bs := newBlockingSession()
	c := &session{ts: bs}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.openStream(ctx, "t1", "1.2.3.4:5")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("openStream returned after %v", d)
	}

	// The abandoned Open finishes later and its stream is closed.
	close(bs.release)
	deadline := time.Now().Add(time.Second)
	for bs.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if bs.closed.Load() != 1 {
		t.Fatalf("late stream closed %d times, want 1", bs.closed.Load())
	}
	if n := c.pendingOpens.Load(); n != 0 {
		t.Fatalf("pendingOpens = %d, want 0", n)
	}
}

func TestOpenStreamStopsWhenSessionEnds(t *testing.T) {
	bs := newBlockingSession()
	defer close(bs.release)
	c := &session{ts: bs}
	time.AfterFunc(100*time.Millisecond, func() { close(bs.done) })

	start := time.Now()
	_, err := c.openStream(context.Background(), "t1", "1.2.3.4:5")
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err = %v, want net.ErrClosed", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("openStream returned after %v", d)
	}
}

// Even if Open never returns, the goroutines of one session stay bounded.
func TestOpenStreamPendingLimit(t *testing.T) {
	bs := newBlockingSession()
	defer close(bs.release)
	c := &session{ts: bs}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	for range maxPendingOpens {
		wg.Go(func() { _, _ = c.openStream(ctx, "t1", "r") })
	}
	for c.pendingOpens.Load() < maxPendingOpens {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := c.openStream(context.Background(), "t1", "r"); !errors.Is(err, errTooManyOpens) {
		t.Fatalf("err = %v, want errTooManyOpens", err)
	}
	cancel()
	wg.Wait()
	if n := bs.opens.Load(); n != maxPendingOpens {
		t.Fatalf("Open called %d times, want %d", n, maxPendingOpens)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestPersisterQueueCap(t *testing.T) {
	var logs syncBuf
	p := newPersister(time.Second)
	p.log = slog.New(slog.NewTextHandler(&logs, nil))
	p.maxQ = 3

	started, release := make(chan struct{}), make(chan struct{})
	var ran atomic.Int32
	p.add(func(context.Context) {
		close(started)
		<-release
		ran.Add(1)
	})
	<-started // the blocked write has left the queue
	for range 8 {
		p.add(func(context.Context) { ran.Add(1) })
	}
	close(release)
	if !p.flush(2 * time.Second) {
		t.Fatal("flush timed out")
	}
	if got := ran.Load(); got != 4 { // the blocked one + a queue of 3
		t.Fatalf("ran %d writes, want 4", got)
	}
	if n := strings.Count(logs.String(), "store write queue is full"); n != 1 {
		t.Fatalf("%d warnings, want 1 (rate-limited):\n%s", n, logs.String())
	}
}
