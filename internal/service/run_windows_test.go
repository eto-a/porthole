// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const handlerTimeout = 5 * time.Second

type execResult struct {
	ssec bool
	code uint32
}

// startHandler runs Execute on channels, without the service control manager.
func startHandler(t *testing.T, run func(ctx context.Context, ready func(), reload <-chan struct{}) error) (chan<- svc.ChangeRequest, <-chan svc.Status, <-chan execResult) {
	t.Helper()
	reqs := make(chan svc.ChangeRequest)
	status := make(chan svc.Status, 16)
	res := make(chan execResult, 1)
	h := &handler{run: run}
	go func() {
		ssec, code := h.Execute(nil, reqs, status)
		res <- execResult{ssec, code}
	}()
	return reqs, status, res
}

func nextStatus(t *testing.T, status <-chan svc.Status) svc.Status {
	t.Helper()
	select {
	case s := <-status:
		return s
	case <-time.After(handlerTimeout):
		t.Fatal("no status report")
		return svc.Status{}
	}
}

func TestHandlerLifecycle(t *testing.T) {
	reloads := make(chan struct{}, 4)
	reqs, status, res := startHandler(t, func(ctx context.Context, ready func(), reload <-chan struct{}) error {
		ready()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-reload:
				reloads <- struct{}{}
			}
		}
	})

	if s := nextStatus(t, status); s.State != svc.StartPending {
		t.Fatalf("first status = %+v, want StartPending", s)
	}
	s := nextStatus(t, status)
	if want := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptParamChange; s.State != svc.Running || s.Accepts != want {
		t.Fatalf("second status = %+v, want Running accepting Stop|Shutdown|ParamChange", s)
	}

	reqs <- svc.ChangeRequest{Cmd: svc.ParamChange}
	select {
	case <-reloads:
	case <-time.After(handlerTimeout):
		t.Fatal("ParamChange did not reach the daemon as a reload")
	}

	reqs <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}
	if s := nextStatus(t, status); s.State != svc.Running {
		t.Errorf("Interrogate answered %+v", s)
	}

	reqs <- svc.ChangeRequest{Cmd: svc.Shutdown}
	if s := nextStatus(t, status); s.State != svc.StopPending {
		t.Errorf("status after Shutdown = %+v, want StopPending", s)
	}
	select {
	case r := <-res:
		if r.ssec || r.code != 0 {
			t.Errorf("result after a requested stop = %+v, want 0", r)
		}
	case <-time.After(handlerTimeout):
		t.Fatal("Execute did not return after Shutdown")
	}
}

func TestHandlerStopBeforeReady(t *testing.T) {
	reqs, status, res := startHandler(t, func(ctx context.Context, _ func(), _ <-chan struct{}) error {
		<-ctx.Done()
		return ctx.Err()
	})
	nextStatus(t, status) // StartPending
	reqs <- svc.ChangeRequest{Cmd: svc.Stop}
	select {
	case r := <-res:
		if r.ssec || r.code != 0 {
			t.Errorf("result = %+v, want 0", r)
		}
	case <-time.After(handlerTimeout):
		t.Fatal("Execute did not return after Stop")
	}
}

func TestHandlerReloadsCoalesce(t *testing.T) {
	gotReload := make(chan struct{})
	release := make(chan struct{})
	reqs, status, res := startHandler(t, func(ctx context.Context, ready func(), reload <-chan struct{}) error {
		ready()
		<-release // the daemon is busy: ParamChange requests pile up
		<-reload
		close(gotReload)
		<-ctx.Done()
		return nil
	})
	nextStatus(t, status)
	nextStatus(t, status)
	for range 3 { // must not block although nobody reads the channel
		select {
		case reqs <- svc.ChangeRequest{Cmd: svc.ParamChange}:
		case <-time.After(handlerTimeout):
			t.Fatal("ParamChange blocked the service handler")
		}
	}
	close(release)
	select {
	case <-gotReload:
	case <-time.After(handlerTimeout):
		t.Fatal("the pending reload was lost")
	}
	reqs <- svc.ChangeRequest{Cmd: svc.Stop}
	<-res
}

func TestHandlerDaemonFailure(t *testing.T) {
	_, status, res := startHandler(t, func(context.Context, func(), <-chan struct{}) error {
		return errors.New("bad configuration")
	})
	nextStatus(t, status)
	select {
	case r := <-res:
		if !r.ssec || r.code == 0 {
			t.Errorf("result of a failed daemon = %+v, want a non-zero service specific code", r)
		}
	case <-time.After(handlerTimeout):
		t.Fatal("Execute did not return after the daemon failed")
	}
}

func TestHandlerDaemonExitsByItself(t *testing.T) {
	_, status, res := startHandler(t, func(context.Context, func(), <-chan struct{}) error { return nil })
	nextStatus(t, status)
	select {
	case r := <-res:
		if !r.ssec || r.code == 0 {
			t.Errorf("result of a daemon that returned without a stop = %+v, want a failure", r)
		}
	case <-time.After(handlerTimeout):
		t.Fatal("Execute did not return")
	}
}

func TestComposeWindowsCommandLineMatchesX(t *testing.T) {
	for _, args := range [][]string{
		{`C:\Program Files\porthole\porthole.exe`, "daemon"},
		{`C:\porthole.exe`, "--name", "a b", `--path=C:\dir with space\`, `say "hi"`, `back\slash\"quote`, "", `\\server\share`, "tab\there"},
	} {
		if got, want := composeWindowsCommandLine(args), windows.ComposeCommandLine(args); got != want {
			t.Errorf("composeWindowsCommandLine(%q) = %q, windows.ComposeCommandLine = %q", args, got, want)
		}
	}
}

func TestSystemDirSDDLParses(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(systemDirSDDL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sd.DACL(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sd.Owner(); err != nil {
		t.Fatal(err)
	}
}
