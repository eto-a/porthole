// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/eto-a/porthole/deploy"
)

// systemSystemdDir is where an administrator's units live (units under /usr/lib belong to packages).
const systemSystemdDir = "/etc/systemd/system"

type systemdManager struct {
	user     bool
	run      Runner
	dir      string      // where the unit file is written
	elevated func() bool // root check; replaced in tests
}

func newSystemd(user bool) (Manager, error) {
	dir := systemSystemdDir
	if user {
		cfg, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("find the systemd user unit directory: %w", err)
		}
		dir = filepath.Join(cfg, "systemd", "user")
	}
	return &systemdManager{user: user, run: execRunner{}, dir: dir, elevated: Elevated}, nil
}

func unitName(name string) string { return name + ".service" }

func (m *systemdManager) unitPath(name string) string { return filepath.Join(m.dir, unitName(name)) }

// ctl runs systemctl (--user for the user manager).
func (m *systemdManager) ctl(ctx context.Context, args ...string) ([]byte, error) {
	if m.user {
		args = append([]string{"--user"}, args...)
	}
	return m.run.Run(ctx, "systemctl", args...)
}

func (m *systemdManager) Install(spec Spec) error {
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
	unit, err := renderSystemdUnit(spec)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if !m.user {
		if err := m.ensureClientUser(ctx); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", m.dir, err)
	}
	if err := writeFileAtomic(m.unitPath(spec.Name), []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write the unit: %w", err)
	}
	st, _ := m.Status(spec.Name) // an error here only means "do not restart afterwards"
	if _, err := m.ctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if _, err := m.ctl(ctx, "enable", "--now", unitName(spec.Name)); err != nil {
		return err
	}
	if st.Running { // enable --now does not restart a running unit, which would keep the old definition
		if _, err := m.ctl(ctx, "restart", unitName(spec.Name)); err != nil {
			return err
		}
	}
	return nil
}

// ensureClientUser creates the porthole-client account (and its group) of the system unit when it is missing, as the
// deb and rpm packages do.
func (m *systemdManager) ensureClientUser(ctx context.Context) error {
	if _, err := m.run.Run(ctx, "id", "-u", ClientUser); err == nil {
		return nil
	}
	_, err := m.run.Run(ctx, "useradd", "--system", "--user-group", "--no-create-home",
		"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", ClientUser)
	if err != nil {
		return fmt.Errorf("create the %s user: %w", ClientUser, err)
	}
	return nil
}

func (m *systemdManager) Uninstall(name string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	if !m.user && !m.elevated() {
		return ErrNotElevated
	}
	ctx := context.Background()
	st, err := m.Status(name)
	if err != nil {
		return err
	}
	if !st.Installed {
		return nil
	}
	if _, err := m.ctl(ctx, "disable", "--now", unitName(name)); err != nil {
		return err
	}
	if err := os.Remove(m.unitPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the unit: %w", err)
	}
	_, err = m.ctl(ctx, "daemon-reload")
	return err
}

func (m *systemdManager) Start(name string) error   { return m.act("start", name) }
func (m *systemdManager) Stop(name string) error    { return m.act("stop", name) }
func (m *systemdManager) Restart(name string) error { return m.act("restart", name) }

func (m *systemdManager) act(verb, name string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	st, err := m.Status(name)
	if err != nil {
		return err
	}
	if !st.Installed {
		return ErrNotInstalled
	}
	_, err = m.ctl(context.Background(), verb, unitName(name))
	return err
}

func (m *systemdManager) Status(name string) (State, error) {
	name, err := checkName(name)
	if err != nil {
		return State{}, err
	}
	out, err := m.ctl(context.Background(), "show", unitName(name), "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "MainPID")
	if err != nil {
		return State{}, err
	}
	return parseSystemdShow(string(out)), nil
}

// parseSystemdShow reads the Key=Value lines of `systemctl show`.
func parseSystemdShow(out string) State {
	props := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	st := State{
		Installed: props["LoadState"] != "" && props["LoadState"] != "not-found",
		Running:   props["ActiveState"] == "active",
	}
	if st.Installed {
		st.Detail = props["ActiveState"]
		if sub := props["SubState"]; sub != "" {
			st.Detail += " (" + sub + ")"
		}
	} else {
		st.Detail = "not installed"
	}
	if pid, err := strconv.Atoi(props["MainPID"]); err == nil && pid > 0 {
		st.PID = pid
	}
	return st
}

// renderSystemdUnit returns the unit text: the embedded unit of deploy/ with the ExecStart and ExecReload lines
// pointing at spec.Exe. The arguments of ExecStart are spec.Args, or those of the embedded unit when Args is empty.
// A --socket in Args is repeated in ExecReload so that `systemctl reload` reaches the same daemon.
func renderSystemdUnit(spec Spec) (string, error) {
	tmpl := unitText(spec.User)
	exe := quoteSystemd(spec.Exe)
	var start, reload bool
	lines := strings.Split(tmpl, "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "ExecStart="):
			_, defArgs, _ := strings.Cut(strings.TrimPrefix(line, "ExecStart="), " ")
			args := defArgs
			if len(spec.Args) > 0 {
				args = quoteSystemdArgs(spec.Args)
			}
			lines[i] = "ExecStart=" + exe + " " + args
			start = true
		case strings.HasPrefix(line, "ExecReload="):
			_, defArgs, _ := strings.Cut(strings.TrimPrefix(line, "ExecReload="), " ")
			args := defArgs
			if sock, ok := socketArg(spec.Args); ok {
				args = "reload --socket " + quoteSystemd(sock)
			}
			lines[i] = "ExecReload=" + exe + " " + args
			reload = true
		}
	}
	if !start || !reload {
		return "", errors.New("internal error: the embedded unit has no ExecStart or ExecReload line")
	}
	return strings.Join(lines, "\n"), nil
}

// socketArg finds the value of --socket in args.
func socketArg(args []string) (string, bool) {
	for i, a := range args {
		if a == "--socket" && i+1 < len(args) {
			return args[i+1], true
		}
		if v, ok := strings.CutPrefix(a, "--socket="); ok {
			return v, true
		}
	}
	return "", false
}

func quoteSystemdArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = quoteSystemd(a)
	}
	return strings.Join(q, " ")
}

// quoteSystemd quotes one word of an ExecStart line. systemd expands specifiers (%x) and variables ($X) in these
// lines, so a literal '%' and '$' are doubled; a word with white space, quotes or a backslash gets double quotes.
func quoteSystemd(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "$", "$$")
	if s != "" && !strings.ContainsAny(s, " \t\"'\\;") {
		return s
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// unitText returns the embedded unit; a Windows checkout may have CRLF line ends, which the unit must not get.
func unitText(user bool) string {
	text := deploy.SystemUnit
	if user {
		text = deploy.UserUnit
	}
	return strings.ReplaceAll(text, "\r\n", "\n")
}
