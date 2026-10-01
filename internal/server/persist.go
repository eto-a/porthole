// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"sync"
	"time"
)

// persistDrainTimeout bounds how long Close waits for queued store writes. A store that has stopped answering must
// not keep the process from exiting; what is still queued then is lost, and port reservations are only a convenience.
const persistDrainTimeout = 10 * time.Second

// persister runs store writes that the registry needs but does not wait for, in the order they were queued, on one
// goroutine. The registry decides under Server.mu and queues under it (queueing never blocks); the disk is touched
// after the lock is gone, so a slow store cannot stall other sessions (the lock is held by every lookup).
// The goroutine exists only while the queue is not empty.
type persister struct {
	timeout time.Duration // per write

	mu      sync.Mutex
	queue   []func(ctx context.Context)
	running bool
	stopped bool
	wg      sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc
}

func newPersister(timeout time.Duration) *persister {
	p := &persister{timeout: timeout}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

// add queues fn. It never blocks and never runs fn on the caller's goroutine.
func (p *persister) add(fn func(ctx context.Context)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return
	}
	p.queue = append(p.queue, fn)
	if !p.running {
		p.running = true
		p.wg.Go(p.run)
	}
}

func (p *persister) run() {
	for {
		p.mu.Lock()
		if len(p.queue) == 0 {
			p.running = false
			p.mu.Unlock()
			return
		}
		fn := p.queue[0]
		p.queue[0] = nil
		p.queue = p.queue[1:]
		p.mu.Unlock()

		ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
		fn(ctx)
		cancel()
	}
}

// flush waits until everything queued is written, at most d; after that it cancels the write in progress and the
// rest fail at once. It reports whether the queue was written in time. No write is accepted afterwards.
func (p *persister) flush(d time.Duration) bool {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()

	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		p.cancel()
		<-done
		return false
	}
}
