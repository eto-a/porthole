// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// scmWaitTimeout bounds the wait for a state change after Start and Stop.
const scmWaitTimeout = 30 * time.Second

// scmPollInterval is how often the state is polled while waiting.
const scmPollInterval = 200 * time.Millisecond

const eventTypes = eventlog.Error | eventlog.Warning | eventlog.Info

type scmManager struct {
	elevated func() bool
}

func newSCM(user bool) (Manager, error) {
	if user {
		return nil, fmt.Errorf("a per-user service on Windows (run `porthole daemon` in a terminal or use Task Scheduler): %w", ErrUnsupported)
	}
	return &scmManager{elevated: Elevated}, nil
}

// connect opens the service control manager with the given access (SC_MANAGER_*). The package mgr asks for full
// access, which a non-elevated user does not have, so reading the state would fail.
func connect(access uint32) (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, access)
	if err != nil {
		return nil, fmt.Errorf("connect to the service control manager: %w", err)
	}
	return &mgr.Mgr{Handle: h}, nil
}

// openService opens one service with the given access (SERVICE_*); the error wraps
// windows.ERROR_SERVICE_DOES_NOT_EXIST when there is no such service.
func openService(m *mgr.Mgr, name string, access uint32) (*mgr.Service, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m.Handle, p, access)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

// withService runs fn on the service opened with access; a missing service is [ErrNotInstalled].
func withService(name string, access uint32, fn func(*mgr.Service) error) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	m, err := connect(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := openService(m, name, access)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return ErrNotInstalled
		}
		return fmt.Errorf("open service %s: %w", name, err)
	}
	defer s.Close()
	return fn(s)
}

func (m *scmManager) Install(spec Spec) error {
	spec, err := spec.normalize()
	if err != nil {
		return err
	}
	if spec.User {
		return fmt.Errorf("a per-user service on Windows: %w", ErrUnsupported)
	}
	if !m.elevated() {
		return ErrNotElevated
	}
	cfg := buildSCMConfig(spec)
	c, err := connect(windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer func() { _ = c.Disconnect() }()

	created := false
	s, err := openService(c, spec.Name, windows.SERVICE_ALL_ACCESS)
	switch {
	case err == nil:
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		s, err = c.CreateService(spec.Name, spec.Exe, mgr.Config{
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
			DisplayName:  cfg.DisplayName,
		}, spec.Args...)
		if err != nil {
			return fmt.Errorf("create service %s: %w", spec.Name, err)
		}
		created = true
	default:
		return fmt.Errorf("open service %s: %w", spec.Name, err)
	}
	defer s.Close()

	if err := applyConfig(s, cfg); err != nil {
		if created {
			_ = s.Delete() // do not leave a half-configured service behind
		}
		return err
	}
	// The source may exist from an earlier install (Install fails on an existing key), so start from scratch.
	_ = eventlog.Remove(spec.Name)
	if err := eventlog.InstallAsEventCreate(spec.Name, eventTypes); err != nil {
		if created {
			_ = s.Delete()
		}
		return fmt.Errorf("register the event log source %s: %w", spec.Name, err)
	}

	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service %s: %w", spec.Name, err)
	}
	if st.State != svc.Stopped { // a running service is restarted to apply the new definition
		if err := stopAndWait(s); err != nil {
			return err
		}
	}
	return startAndWait(s)
}

// applyConfig sets the definition of cfg on s: LocalSystem, automatic delayed start, the restart ladder.
func applyConfig(s *mgr.Service, cfg scmConfig) error {
	err := s.UpdateConfig(mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ErrorControl:     mgr.ErrorNormal,
		BinaryPathName:   cfg.CommandLine,
		ServiceStartName: "LocalSystem",
		DisplayName:      cfg.DisplayName,
		Description:      cfg.Description,
	})
	if err != nil {
		return fmt.Errorf("configure service %s: %w", cfg.Name, err)
	}
	actions := make([]mgr.RecoveryAction, len(scmRecoveryDelays))
	for i, d := range scmRecoveryDelays {
		actions[i] = mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: d}
	}
	if err := s.SetRecoveryActions(actions, uint32(scmResetPeriod/time.Second)); err != nil {
		return fmt.Errorf("set the recovery actions of %s: %w", cfg.Name, err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(cfg.RecoveryOnNonCrash); err != nil {
		return fmt.Errorf("set the recovery actions of %s: %w", cfg.Name, err)
	}
	return nil
}

func (m *scmManager) Uninstall(name string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	if !m.elevated() {
		return ErrNotElevated
	}
	err = withService(name, windows.SERVICE_ALL_ACCESS, func(s *mgr.Service) error {
		if err := stopAndWait(s); err != nil {
			return err
		}
		if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("delete service %s: %w", name, err)
		}
		return nil
	})
	if err != nil && !errors.Is(err, ErrNotInstalled) {
		return err
	}
	_ = eventlog.Remove(name) // best effort: the key may not exist
	return nil
}

func (*scmManager) Start(name string) error {
	return withService(name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS, startAndWait)
}

func (*scmManager) Stop(name string) error {
	return withService(name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS, stopAndWait)
}

func (*scmManager) Restart(name string) error {
	return withService(name, windows.SERVICE_START|windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS, func(s *mgr.Service) error {
		if err := stopAndWait(s); err != nil {
			return err
		}
		return startAndWait(s)
	})
}

func (*scmManager) Status(name string) (State, error) {
	var st State
	err := withService(name, windows.SERVICE_QUERY_STATUS, func(s *mgr.Service) error {
		q, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service %s: %w", s.Name, err)
		}
		st = State{Installed: true, Running: q.State == svc.Running, PID: int(q.ProcessId), Detail: stateName(q.State)}
		return nil
	})
	if errors.Is(err, ErrNotInstalled) {
		return State{Detail: "not installed"}, nil
	}
	return st, err
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "STOPPED"
	case svc.StartPending:
		return "START_PENDING"
	case svc.StopPending:
		return "STOP_PENDING"
	case svc.Running:
		return "RUNNING"
	case svc.ContinuePending:
		return "CONTINUE_PENDING"
	case svc.PausePending:
		return "PAUSE_PENDING"
	case svc.Paused:
		return "PAUSED"
	default:
		return fmt.Sprintf("state %d", uint32(s))
	}
}

// startAndWait starts s and waits until it reports Running (the daemon does that once the pipe listens and the
// tunnels file is loaded). A service that is already running is fine.
func startAndWait(s *mgr.Service) error {
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start service %s: %w", s.Name, err)
	}
	return waitState(s, svc.Running)
}

// stopAndWait asks s to stop and waits until it has. A service that is not running is fine.
func stopAndWait(s *mgr.Service) error {
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop service %s: %w", s.Name, err)
	}
	return waitState(s, svc.Stopped)
}

func waitState(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(scmWaitTimeout)
	for {
		q, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service %s: %w", s.Name, err)
		}
		if q.State == want {
			return nil
		}
		if want == svc.Running && q.State == svc.Stopped {
			return fmt.Errorf("service %s stopped while starting (see the event log and %%ProgramData%%\\porthole\\logs)", s.Name)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service %s is %s, expected %s after %s", s.Name, stateName(q.State), stateName(want), scmWaitTimeout)
		}
		time.Sleep(scmPollInterval)
	}
}
