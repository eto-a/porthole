// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
)

// LaunchdLabelPrefix is the reverse-DNS prefix of the launchd label; the label is the prefix plus the service name.
const LaunchdLabelPrefix = "io.github.eto-a."

// launchdThrottle is the minimum number of seconds between two starts of a job that keeps failing. launchd cannot
// exclude an exit code from KeepAlive (unlike systemd's RestartPreventExitStatus=78), so a broken configuration is
// retried at this pace and logged (ADR 0006 section 1).
const launchdThrottle = 10

type launchdManager struct {
	user     bool
	run      Runner
	dir      string // where the plist is written
	logDir   string // default log directory of this variant
	domain   string // "system" or "gui/<uid>"
	elevated func() bool
}

func newLaunchd(user bool) (Manager, error) {
	m := &launchdManager{
		run:      execRunner{},
		elevated: Elevated,
		user:     user,
		dir:      "/Library/LaunchDaemons",
		logDir:   "/Library/Logs/porthole",
		domain:   "system",
	}
	if user {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("find the home directory: %w", err)
		}
		m.dir = filepath.Join(home, "Library", "LaunchAgents")
		m.logDir = filepath.Join(home, "Library", "Logs", "porthole")
		m.domain = "gui/" + strconv.Itoa(os.Getuid())
	}
	return m, nil
}

func launchdLabel(name string) string { return LaunchdLabelPrefix + name }

func (m *launchdManager) plistPath(name string) string {
	return filepath.Join(m.dir, launchdLabel(name)+".plist")
}

func (m *launchdManager) target(name string) string { return m.domain + "/" + launchdLabel(name) }

func (m *launchdManager) ctl(ctx context.Context, args ...string) ([]byte, error) {
	return m.run.Run(ctx, "launchctl", args...)
}

func (m *launchdManager) Install(spec Spec) error {
	spec, err := spec.normalize()
	if err != nil {
		return err
	}
	if spec.User != m.user {
		return errors.New("internal error: Spec.User does not match the manager")
	}
	if !m.user && !m.elevated() {
		return ErrNotElevated
	}
	if spec.LogDir == "" {
		spec.LogDir = m.logDir
	}
	data, err := renderLaunchdPlist(spec)
	if err != nil {
		return err
	}
	for _, d := range []string{m.dir, spec.LogDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	path := m.plistPath(spec.Name)
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write the plist: %w", err)
	}
	ctx := context.Background()
	if m.loaded(ctx, spec.Name) { // reload to apply the new definition (this also restarts a running job)
		if _, err := m.ctl(ctx, "bootout", m.target(spec.Name)); err != nil {
			return err
		}
	}
	return m.bootstrap(ctx, spec.Name)
}

// bootstrap loads the plist into the domain; with RunAtLoad that starts the job. A job that was disabled with
// `launchctl disable` is enabled first (bootstrap would fail with an I/O error otherwise).
func (m *launchdManager) bootstrap(ctx context.Context, name string) error {
	_, _ = m.ctl(ctx, "enable", m.target(name)) // best effort: fails on a system without a disabled-jobs record
	_, err := m.ctl(ctx, "bootstrap", m.domain, m.plistPath(name))
	return err
}

func (m *launchdManager) loaded(ctx context.Context, name string) bool {
	_, err := m.ctl(ctx, "print", m.target(name))
	return err == nil
}

func (m *launchdManager) Uninstall(name string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	if !m.user && !m.elevated() {
		return ErrNotElevated
	}
	ctx := context.Background()
	if m.loaded(ctx, name) {
		if _, err := m.ctl(ctx, "bootout", m.target(name)); err != nil {
			return err
		}
	}
	if err := os.Remove(m.plistPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the plist: %w", err)
	}
	return nil
}

func (m *launchdManager) installed(name string) bool {
	_, err := os.Stat(m.plistPath(name))
	return err == nil
}

func (m *launchdManager) Start(name string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	if !m.installed(name) {
		return ErrNotInstalled
	}
	ctx := context.Background()
	if m.loaded(ctx, name) {
		_, err = m.ctl(ctx, "kickstart", m.target(name)) // starts it when it is not running, otherwise does nothing
		return err
	}
	return m.bootstrap(ctx, name)
}

// Stop unloads the job: with KeepAlive a plain kill would be answered by a restart.
func (m *launchdManager) Stop(name string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	if !m.installed(name) {
		return ErrNotInstalled
	}
	ctx := context.Background()
	if !m.loaded(ctx, name) {
		return nil
	}
	_, err = m.ctl(ctx, "bootout", m.target(name))
	return err
}

func (m *launchdManager) Restart(name string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	if !m.installed(name) {
		return ErrNotInstalled
	}
	ctx := context.Background()
	if m.loaded(ctx, name) {
		_, err = m.ctl(ctx, "kickstart", "-k", m.target(name))
		return err
	}
	return m.bootstrap(ctx, name)
}

func (m *launchdManager) Status(name string) (State, error) {
	name, err := checkName(name)
	if err != nil {
		return State{}, err
	}
	st := State{Installed: m.installed(name)}
	out, err := m.ctl(context.Background(), "print", m.target(name))
	if err != nil { // not loaded
		st.Detail = "not loaded"
		if !st.Installed {
			st.Detail = "not installed"
		}
		return st, nil
	}
	loaded := parseLaunchdPrint(string(out))
	st.Running = loaded.Running
	st.PID = loaded.PID
	st.Detail = loaded.Detail
	return st, nil
}

var (
	launchdStateRE = regexp.MustCompile(`(?m)^\tstate = (\S+)`)
	launchdPIDRE   = regexp.MustCompile(`(?m)^\tpid = (\d+)`)
)

// parseLaunchdPrint reads the top-level "state" and "pid" of `launchctl print <target>`.
func parseLaunchdPrint(out string) State {
	st := State{Installed: true, Detail: "loaded"}
	if m := launchdStateRE.FindStringSubmatch(out); m != nil {
		st.Detail = "state = " + m[1]
		st.Running = m[1] == "running"
	}
	if m := launchdPIDRE.FindStringSubmatch(out); m != nil {
		st.PID, _ = strconv.Atoi(m[1])
	}
	return st
}

// renderLaunchdPlist returns the plist of the job (ADR 0006 section 1). The text is written with explicit XML
// escaping of every value; nothing is spliced in through a template.
func renderLaunchdPlist(spec Spec) ([]byte, error) {
	logDir := spec.LogDir
	if logDir == "" {
		return nil, errors.New("the log directory is empty")
	}
	var b bytes.Buffer
	str := func(indent, s string) error {
		b.WriteString(indent + "<string>")
		if err := xml.EscapeText(&b, []byte(s)); err != nil {
			return err
		}
		b.WriteString("</string>\n")
		return nil
	}
	key := func(k string) { b.WriteString("\t<key>" + k + "</key>\n") }

	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`)
	key("Label")
	if err := str("\t", launchdLabel(spec.Name)); err != nil {
		return nil, err
	}
	key("ProgramArguments")
	b.WriteString("\t<array>\n")
	for _, a := range append([]string{spec.Exe}, spec.Args...) {
		if err := str("\t\t", a); err != nil {
			return nil, err
		}
	}
	b.WriteString("\t</array>\n")
	key("RunAtLoad")
	b.WriteString("\t<true/>\n")
	key("KeepAlive")
	b.WriteString("\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n")
	key("ThrottleInterval")
	b.WriteString("\t<integer>" + strconv.Itoa(launchdThrottle) + "</integer>\n")
	key("ProcessType")
	b.WriteString("\t<string>Background</string>\n")
	key("StandardOutPath")
	if err := str("\t", path.Join(filepath.ToSlash(logDir), spec.Name+".out.log")); err != nil {
		return nil, err
	}
	key("StandardErrorPath")
	if err := str("\t", path.Join(filepath.ToSlash(logDir), spec.Name+".err.log")); err != nil {
		return nil, err
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes(), nil
}
