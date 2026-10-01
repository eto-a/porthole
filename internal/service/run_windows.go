// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Event IDs of the messages in the Windows event log (EventCreate.exe accepts 1 to 1000).
const (
	eventStarted = 1
	eventStopped = 2
	eventFatal   = 3
)

// stopHint is the time the service control manager is told to wait for the daemon to stop.
const stopHint = 30 * time.Second

// IsService reports whether the process was started by the Windows service control manager.
func IsService() (bool, error) {
	ok, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf("detect a Windows service: %w", err)
	}
	return ok, nil
}

// RunService runs the daemon as the Windows service name and returns when the service has stopped. run starts the
// daemon: it calls ready once the pipe listens and the tunnels file is loaded (the service then reports Running;
// the same point as READY=1 on Linux), returns when ctx is cancelled (Stop or Shutdown) and receives a value on
// reload for every ParamChange (`sc control name paramchange`), the Windows SIGHUP. The channel is buffered and
// coalesces: a reload requested while one is pending is not queued twice. Start, stop and a fatal error are
// written to the event log source name when it exists.
func RunService(name string, run func(ctx context.Context, ready func(), reload <-chan struct{}) error) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	h := &handler{run: run}
	if l, err := eventlog.Open(name); err == nil { // no source (not installed by us): no event log messages
		h.log = l
		defer l.Close()
	}
	if err := svc.Run(name, h); err != nil {
		return fmt.Errorf("run service %s: %w", name, err)
	}
	return nil
}

// handler implements svc.Handler for the daemon.
type handler struct {
	run func(ctx context.Context, ready func(), reload <-chan struct{}) error
	log *eventlog.Log // may be nil
}

func (h *handler) logInfo(id uint32, msg string) {
	if h.log != nil {
		_ = h.log.Info(id, msg)
	}
}

func (h *handler) logError(id uint32, msg string) {
	if h.log != nil {
		_ = h.log.Error(id, msg)
	}
}

// Execute implements svc.Handler.
func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptParamChange

	status <- svc.Status{State: svc.StartPending, WaitHint: uint32(stopHint / time.Millisecond)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reload := make(chan struct{}, 1)
	readyCh := make(chan struct{})
	var once sync.Once
	ready := func() { once.Do(func() { close(readyCh) }) }
	done := make(chan error, 1)
	go func() { done <- h.run(ctx, ready, reload) }()

	var running <-chan struct{} = readyCh
	for {
		select {
		case <-running:
			running = nil
			status <- svc.Status{State: svc.Running, Accepts: accepted}
			h.logInfo(eventStarted, "the porthole daemon started")

		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.ParamChange:
				select {
				case reload <- struct{}{}:
				default: // one is already pending
				}
			case svc.Stop, svc.Shutdown:
				cancel()
				return h.stopping(status, done)
			}

		case err := <-done: // the daemon ended on its own
			return h.ended(err, false)
		}
	}
}

// stopping reports StopPending until the daemon has returned, then the exit code.
func (h *handler) stopping(status chan<- svc.Status, done <-chan error) (bool, uint32) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	checkpoint := uint32(1)
	status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: uint32(stopHint / time.Millisecond)}
	for {
		select {
		case err := <-done:
			return h.ended(err, true)
		case <-tick.C:
			checkpoint++
			status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: uint32(stopHint / time.Millisecond)}
		}
	}
}

// ended maps the result of the daemon to the exit code of the service: 0 after a requested stop, 1 (a service
// specific error) when the daemon failed or ended by itself.
func (h *handler) ended(err error, stopRequested bool) (bool, uint32) {
	switch {
	case err != nil && (!stopRequested || !errors.Is(err, context.Canceled)):
		h.logError(eventFatal, "the porthole daemon failed: "+err.Error())
		return true, 1
	case !stopRequested:
		h.logError(eventFatal, "the porthole daemon exited without a stop request")
		return true, 1
	default:
		h.logInfo(eventStopped, "the porthole daemon stopped")
		return false, 0
	}
}
