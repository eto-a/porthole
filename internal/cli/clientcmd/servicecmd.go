// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/clientconfig"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/service"
)

// defaultTunnelsFile is written next to the config file when the service is installed without a tunnels file: no
// tunnels, so that installing never publishes anything by accident, and `porthole reload` has a file to read.
const defaultTunnelsFile = "# Tunnels that the porthole service keeps up. See https://github.com/eto-a/porthole (docs/client.md).\n" +
	"# After editing run `porthole reload`: the whole file is checked first and the running tunnels stay untouched\n" +
	"# if it is invalid.\n" +
	"version: 1\n" +
	"tunnels: {}\n"

// serviceFlags are the flags of `porthole service`.
type serviceFlags struct {
	user    bool
	tunnels string
	allow   []string

	allowUnsafe bool // --allow-unsafe-path
}

// serviceResult is the --json output of the service commands. Config, Tunnels and Socket are set by install.
type serviceResult struct {
	Action   string        `json:"action"`
	Name     string        `json:"name"`
	User     bool          `json:"user"`
	Exe      string        `json:"exe,omitempty"`
	Args     []string      `json:"args,omitempty"`
	Config   string        `json:"config,omitempty"`
	Tunnels  string        `json:"tunnels,omitempty"`
	Socket   string        `json:"socket,omitempty"`
	Copied   bool          `json:"copied_credentials,omitempty"` // the config was taken from the user's config file
	Warnings []string      `json:"warnings,omitempty"`
	Service  *serviceState `json:"service,omitempty"`
	API      *apiState     `json:"api,omitempty"`
}

type serviceState struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// apiState is what the local API of the daemon said (`status`), or why it did not answer.
type apiState struct {
	Socket string           `json:"socket"`
	Status *localapi.Status `json:"status,omitempty"`
	Error  string           `json:"error,omitempty"`
}

func (a *app) newServiceCmd() *cobra.Command {
	var f serviceFlags
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Install and control the porthole client as a system service",
		Long: "Manage the porthole client daemon as an operating system service: a systemd unit on Linux, a launchd job on\n" +
			"macOS and a Windows service. By default the system-wide service is managed, which needs root or Administrator\n" +
			"(porthole never elevates itself: run it from a terminal that already has the rights). --user selects the\n" +
			"per-user variant (a systemd user unit or a LaunchAgent); Windows has none, see docs/client.md for Task Scheduler.\n\n" +
			"The system service reads its configuration from the system directory (Linux /etc/porthole, macOS\n" +
			"/Library/Application Support/porthole, Windows %ProgramData%\\porthole) and serves the local API on the system\n" +
			"endpoint, which `porthole status`, `http`, `reload` and the other commands find by themselves.",
	}
	cmd.PersistentFlags().BoolVar(&f.user, "user", false, "manage the per-user service (systemd user unit, LaunchAgent) instead of the system one")

	install := &cobra.Command{
		Use:   "install",
		Short: "Register the service, enable it at boot and start it",
		Long: "Register the service with the porthole binary that is running now (so put it in its final place first), check\n" +
			"the configuration, enable the service at boot (or login with --user) and start it. Running it again updates\n" +
			"the definition and restarts the service.\n\n" +
			"The service needs credentials: run `porthole login --system <server-url> <token>` (or `porthole join --system\n" +
			"<link>`) first. If the system config file does not exist yet but your own does, install copies it. An existing\n" +
			"config.yaml or tunnels.yaml is never overwritten; a missing tunnels.yaml is created empty.\n\n" +
			"--allow admits a user or group to the service's named pipe on Windows; it may be repeated. Those users are\n" +
			"unprivileged peers, like the members of the porthole-client group on Linux: they may publish loopback\n" +
			"targets (and what allow_remote lists), close their own tunnels and nothing else. Administrators and SYSTEM\n" +
			"keep full control.\n\n" +
			"The service runs with the rights of the system, so install refuses a binary, or an explicit --config or\n" +
			"--tunnels file, that a user who is not an administrator could replace or edit (the file, or a directory above\n" +
			"it, is writable by them). Put the binary where only administrators can write (C:\\Program Files\\porthole\\ on\n" +
			"Windows, /usr/local/bin on Linux and macOS); --allow-unsafe-path overrides the check knowingly.",
		Example: "  sudo porthole service install\n" +
			"  porthole service install --user\n" +
			"  porthole service install --allow BUILTIN\\Users          (Windows, elevated terminal)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.runServiceInstall(cmd, f) },
	}
	install.Flags().StringVar(&f.tunnels, "tunnels", "", "tunnels file (default: tunnels.yaml next to the config file)")
	install.Flags().StringArrayVar(&f.allow, "allow", nil, "user or group admitted to the service's pipe (Windows); repeatable")
	install.Flags().BoolVar(&f.allowUnsafe, "allow-unsafe-path", false,
		"install although the binary or a file of the service can be changed by users who are not administrators")

	cmd.AddCommand(install)
	for _, c := range []struct {
		verb, short string
		do          func(service.Manager, string) error
	}{
		{"uninstall", "Stop the service and remove it (the configuration files stay)", service.Manager.Uninstall},
		{"start", "Start the service", service.Manager.Start},
		{"stop", "Stop the service", service.Manager.Stop},
		{"restart", "Restart the service", service.Manager.Restart},
	} {
		cmd.AddCommand(&cobra.Command{
			Use:   c.verb,
			Short: c.short,
			Args:  cobra.NoArgs,
			RunE:  func(cmd *cobra.Command, _ []string) error { return a.runServiceVerb(cmd, f.user, c.verb, c.do) },
		})
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show the state of the service and what the daemon says over its local API",
		Long: "Show whether the service is installed and running, and ask the daemon over its local API (the same data as\n" +
			"`porthole status`). It exits with status 0 even when the service is not installed or not running; read the\n" +
			"state from the output or from --json.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.runServiceStatus(cmd, f.user) },
	})
	return cmd
}

// manager returns the service manager, mapping "this OS has no such service" to advice.
func (a *app) manager(user bool) (service.Manager, error) {
	if a.d.newService == nil {
		return nil, errors.New("services are not available in this build")
	}
	m, err := a.d.newService(user)
	if err != nil {
		return nil, serviceErr(err, "service", user)
	}
	return m, nil
}

// serviceEndpoint is the daemon endpoint of the service: --socket, else the system endpoint (user: the user one).
func (a *app) serviceEndpoint(user bool) (string, error) {
	switch {
	case a.socket != "":
		return a.socket, nil
	case user:
		if p := a.d.userSocketPath(); p != "" {
			return p, nil
		}
		return "", errors.New("cannot determine the user socket path; use --socket")
	default:
		return localapi.SystemSocketPath, nil
	}
}

// serviceErr turns the errors of the service package into advice.
func serviceErr(err error, command string, user bool) error {
	switch {
	case errors.Is(err, service.ErrNotElevated), errors.Is(err, fs.ErrPermission):
		msg := elevationHint(runtime.GOOS, command)
		if !errors.Is(err, service.ErrNotElevated) {
			msg += " (" + err.Error() + ")"
		}
		return &explainedError{msg: msg, err: err}
	case errors.Is(err, service.ErrUnsupported) && user && runtime.GOOS == "windows":
		return &explainedError{
			msg: "Windows has no per-user service. Run `porthole daemon` in a terminal, or start it at logon with Task " +
				"Scheduler (see \"Run as a service\" in docs/client.md); or drop --user to manage the system service from an " +
				"Administrator terminal",
			err: err,
		}
	case errors.Is(err, service.ErrNotInstalled):
		return &explainedError{msg: "the service is not installed; run `porthole service install` first", err: err}
	}
	return err
}

// elevationHint tells the user how to run `porthole <command>` with the rights it needs.
func elevationHint(goos, command string) string {
	if goos == "windows" {
		return "`porthole " + command + "` needs Administrator rights: run it in a terminal opened with \"Run as administrator\""
	}
	return "`porthole " + command + "` needs root: run it with sudo (sudo porthole " + command + ")"
}

func (a *app) runServiceVerb(cmd *cobra.Command, user bool, verb string, do func(service.Manager, string) error) error {
	m, err := a.manager(user)
	if err != nil {
		return err
	}
	if err := do(m, service.DefaultName); err != nil {
		return serviceErr(err, "service "+verb, user)
	}
	res := serviceResult{Action: verb, Name: service.DefaultName, User: user}
	if st, err := m.Status(service.DefaultName); err == nil {
		res.Service = &serviceState{Installed: st.Installed, Running: st.Running, PID: st.PID, Detail: st.Detail}
	}
	if jsonout.Enabled(cmd) {
		return jsonout.Write(cmd.OutOrStdout(), res)
	}
	past := map[string]string{"uninstall": "Uninstalled", "start": "Started", "stop": "Stopped", "restart": "Restarted"}[verb]
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s the %s service %q\n", past, scope(user), service.DefaultName)
	return err
}

func scope(user bool) string {
	if user {
		return "user"
	}
	return "system"
}

// installPaths resolves the config file, the tunnels file and the socket the service will use.
func (a *app) installPaths(f serviceFlags) (cfg, tunnels, socket string, err error) {
	switch {
	case f.user:
		if cfg, err = a.path(); err != nil {
			return "", "", "", err
		}
	case a.configPath != "":
		cfg = a.configPath
	default:
		dir, derr := a.systemDir("service install")
		if derr != nil {
			return "", "", "", derr
		}
		cfg = filepath.Join(dir, "config.yaml")
	}
	if f.tunnels != "" {
		tunnels = f.tunnels
	} else {
		tunnels = filepath.Join(filepath.Dir(cfg), tunnelsFileName)
	}
	if socket, err = a.serviceEndpoint(f.user); err != nil {
		return "", "", "", err
	}
	return cfg, tunnels, socket, nil
}

// systemDir creates (or checks) the system configuration directory and returns it. It needs elevation.
func (a *app) systemDir(command string) (string, error) {
	if a.d.prepareDir == nil {
		return "", errors.New("the system directory is not available in this build")
	}
	dir, err := a.d.prepareDir()
	if err != nil {
		return "", serviceErr(err, command, false)
	}
	return dir, nil
}

func (a *app) runServiceInstall(cmd *cobra.Command, f serviceFlags) error {
	if len(f.allow) > 0 {
		if runtime.GOOS != "windows" {
			return usageErr(errors.New("--allow is for the Windows pipe; on Linux add the user to the porthole-client group " +
				"(`sudo usermod -aG porthole-client <user>`), on macOS use sudo (the socket is for root)"))
		}
		for _, p := range f.allow {
			if strings.TrimSpace(p) == "" {
				return usageErr(errors.New("--allow needs a user or group name"))
			}
		}
	}
	m, err := a.manager(f.user)
	if err != nil {
		return err
	}
	exe, err := a.executable()
	if err != nil {
		return err
	}
	cfgPath, tunnelsPath, socket, err := a.installPaths(f)
	if err != nil {
		return err
	}
	res := serviceResult{
		Action: "install", Name: service.DefaultName, User: f.user, Exe: exe,
		Config: cfgPath, Tunnels: tunnelsPath, Socket: socket,
	}
	if w := suspiciousExe(exe, os.TempDir()); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	unsafeWarnings, err := a.checkServicePaths(f, exe, cfgPath, tunnelsPath)
	if err != nil {
		return err
	}
	res.Warnings = append(res.Warnings, unsafeWarnings...)

	// Check everything before the system is changed.
	cfg, copied, err := a.ensureServiceConfig(cfgPath, !f.user && a.configPath == "")
	if err != nil {
		return err
	}
	res.Copied = copied
	tf, err := a.ensureTunnelsFile(tunnelsPath)
	if err != nil {
		return err
	}
	if cfg.Server == "" && (tf == nil || tf.Server == "") {
		return configErr(fmt.Errorf("no server URL in %s or %s: run `porthole login%s <server-url> <token>`", cfgPath, tunnelsPath,
			map[bool]string{true: "", false: " --system"}[f.user]))
	}

	spec := service.Spec{Exe: exe, Args: daemonArgs(cfgPath, tunnelsPath, socket, f.allow), User: f.user}
	res.Args = spec.Args
	chownIfNeeded := func() (bool, error) { return false, nil }
	if !f.user && a.d.fixOwnership != nil {
		// Only the files of the default system directory are handed to the service account; a file elsewhere is the
		// user's own.
		var cfgFix, tunFix string
		if a.configPath == "" {
			cfgFix = cfgPath
			if f.tunnels == "" {
				tunFix = tunnelsPath
			}
		}
		chownIfNeeded = func() (bool, error) { return a.d.fixOwnership(cfgFix, tunFix) }
	}

	// The account of the service may not exist before Install; hand the files over afterwards and restart. If the
	// service could not start for want of that, Install reports an error that the restart then cures.
	_, _ = chownIfNeeded()
	installErr := m.Install(spec)
	changed, ferr := chownIfNeeded()
	if ferr != nil {
		res.Warnings = append(res.Warnings, "could not give the service account access to the configuration: "+ferr.Error())
	}
	if changed {
		if rerr := m.Restart(service.DefaultName); installErr != nil && rerr == nil {
			installErr = nil
		} else if installErr == nil && rerr != nil {
			installErr = rerr
		}
	}
	if installErr != nil {
		return serviceErr(installErr, "service install", f.user)
	}
	if st, err := m.Status(service.DefaultName); err == nil {
		res.Service = &serviceState{Installed: st.Installed, Running: st.Running, PID: st.PID, Detail: st.Detail}
	}
	if jsonout.Enabled(cmd) {
		return jsonout.Write(cmd.OutOrStdout(), res)
	}
	return printInstall(cmd.OutOrStdout(), cmd.ErrOrStderr(), res)
}

// checkServicePaths refuses a system service whose binary, or whose explicitly named config or tunnels file, could be
// changed by a user who is not an administrator: the service runs with the rights of the system, so whoever can
// change these runs code with them (or redirects the daemon to a server of their choosing and publishes what they
// like). The files of the default system directory are checked when it is prepared. A per-user service runs as the
// user, who can change everything it uses anyway. With --allow-unsafe-path the findings are returned as warnings.
func (a *app) checkServicePaths(f serviceFlags, exe, cfgPath, tunnelsPath string) ([]string, error) {
	if f.user || a.d.checkPath == nil {
		return nil, nil
	}
	paths := []string{exe}
	if a.configPath != "" {
		paths = append(paths, cfgPath)
	}
	if f.tunnels != "" {
		paths = append(paths, tunnelsPath)
	}
	var warnings []string
	for _, p := range paths {
		err := a.d.checkPath(p)
		if err == nil {
			continue
		}
		var unsafe *service.UnsafePathError
		if !errors.As(err, &unsafe) {
			return nil, fmt.Errorf("check that %s is safe for a system service: %w", p, err)
		}
		if f.allowUnsafe {
			warnings = append(warnings, fmt.Sprintf("%s can be changed by users who are not administrators (%s); "+
				"installed anyway because of --allow-unsafe-path", p, unsafe))
			continue
		}
		return nil, &explainedError{msg: unsafePathAdvice(runtime.GOOS, p, unsafe), err: err}
	}
	return warnings, nil
}

// unsafePathAdvice explains why a file is refused for a system service and what to do about it.
func unsafePathAdvice(goos, p string, err *service.UnsafePathError) string {
	where := "/usr/local/bin"
	if goos == "windows" {
		where = `C:\Program Files\porthole\`
	}
	return fmt.Sprintf("%s cannot be used by the system service: %s. A service runs with the rights of the system, so a file "+
		"that users who are not administrators can change would give them those rights. Put the binary in a place only "+
		"administrators can write (%s) and run `porthole service install` from there, or use --allow-unsafe-path to accept "+
		"the risk", p, err, where)
}

func printInstall(out, errOut io.Writer, r serviceResult) error {
	for _, w := range r.Warnings {
		fmt.Fprintln(errOut, "warning:", w)
	}
	fmt.Fprintf(out, "Installed the %s service %q.\n", scope(r.User), r.Name)
	fmt.Fprintf(out, "  command:  %s\n", strings.Join(append([]string{r.Exe}, r.Args...), " "))
	fmt.Fprintf(out, "  config:   %s\n", r.Config)
	if r.Copied {
		fmt.Fprintln(out, "            (copied from your own config file)")
	}
	fmt.Fprintf(out, "  tunnels:  %s\n", r.Tunnels)
	fmt.Fprintf(out, "  endpoint: %s\n", r.Socket)
	if r.Service != nil {
		fmt.Fprintf(out, "  state:    %s\n", describeState(*r.Service))
	}
	_, err := fmt.Fprintln(out, "Check it with `porthole service status`.")
	return err
}

func describeState(s serviceState) string {
	switch {
	case !s.Installed:
		return "not installed"
	case s.Running && s.PID > 0:
		return fmt.Sprintf("running (pid %d)", s.PID)
	case s.Running:
		return "running"
	case s.Detail != "":
		return "not running (" + s.Detail + ")"
	default:
		return "not running"
	}
}

// executable returns the absolute path of the running binary with symbolic links resolved.
func (a *app) executable() (string, error) {
	if a.d.executable == nil {
		return "", errors.New("cannot determine the path of the porthole binary")
	}
	exe, err := a.d.executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine the path of the porthole binary: %w", err)
	}
	return exe, nil
}

// suspiciousExe warns about a binary in a place that is cleaned up or not meant to hold programs.
func suspiciousExe(exe, tmp string) string {
	lower := strings.ToLower(filepath.ToSlash(exe))
	if tmp != "" && strings.HasPrefix(lower, strings.ToLower(filepath.ToSlash(filepath.Clean(tmp)))+"/") ||
		strings.Contains(lower, "/downloads/") || strings.Contains(lower, "/go-build") {
		return exe + " looks like a temporary or download location; the service keeps pointing at it. " +
			"Move the binary to its final place and run `porthole service install` again"
	}
	return ""
}

// daemonArgs is the command line of the service: always explicit, the socket included (the Linux unit copies it to
// ExecReload, so that reload reaches this daemon).
func daemonArgs(cfg, tunnels, socket string, allow []string) []string {
	args := []string{"daemon", "--config", cfg, "--tunnels", tunnels, "--socket", socket}
	for _, p := range allow {
		args = append(args, "--allow", p)
	}
	return args
}

// ensureServiceConfig checks that the config file the service will read holds a valid token (and server, when it
// has one). A missing system config file is taken from the user's own one when there is one (copied is true then).
// An existing file is never changed.
func (a *app) ensureServiceConfig(path string, mayCopy bool) (cfg fileConfig, copied bool, err error) {
	cfg, err = loadConfig(path)
	if err != nil {
		return cfg, false, configErr(err)
	}
	if _, statErr := os.Stat(path); mayCopy && errors.Is(statErr, fs.ErrNotExist) {
		if upath, uerr := defaultConfigPath(a.d.userConfigDir); uerr == nil {
			ucfg, lerr := loadConfig(upath)
			tok, terr := ucfg.resolveToken(upath)
			if lerr == nil && terr == nil && ucfg.Server != "" && tok != "" {
				cfg = fileConfig{Server: ucfg.Server, Token: tok}
				if err := saveConfig(path, cfg); err != nil {
					return cfg, false, err
				}
				copied = true
			}
		}
	}
	if cfg.Server == "" && cfg.Token == "" && cfg.TokenFile == "" {
		return cfg, false, configErr(fmt.Errorf("no credentials in %s: run `porthole login%s <server-url> <token>` "+
			"(or `porthole join`) first", path, map[bool]string{true: " --system", false: ""}[mayCopy]))
	}
	tok, err := cfg.resolveToken(path)
	if err != nil {
		return cfg, false, configErr(err)
	}
	if _, err := auth.Parse(tok); err != nil {
		return cfg, false, configErr(fmt.Errorf("the token in %s is malformed (expected ph_<id>_<secret>)", path))
	}
	if cfg.Server != "" {
		if _, err := client.ConnectURL(cfg.Server); err != nil {
			return cfg, false, configErr(fmt.Errorf("the server in %s: %w", path, err))
		}
	}
	return cfg, copied, nil
}

// ensureTunnelsFile validates the tunnels file and returns it, or creates an empty one when there is none (the
// result is nil then).
func (a *app) ensureTunnelsFile(path string) (*clientconfig.File, error) {
	_, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("create the directory of %s: %w", path, err)
		}
		if err := os.WriteFile(path, []byte(defaultTunnelsFile), 0o640); err != nil { //nolint:gosec // no secrets; the service account reads it through its group
			return nil, fmt.Errorf("create %s: %w", path, err)
		}
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("check %s: %w", path, err)
	}
	f, err := clientconfig.Load(path)
	if err != nil {
		return nil, configErr(err)
	}
	return f, nil
}

func (a *app) runServiceStatus(cmd *cobra.Command, user bool) error {
	m, err := a.manager(user)
	if err != nil {
		return err
	}
	st, err := m.Status(service.DefaultName)
	if err != nil {
		return serviceErr(err, "service status", user)
	}
	res := serviceResult{
		Action: "status", Name: service.DefaultName, User: user,
		Service: &serviceState{Installed: st.Installed, Running: st.Running, PID: st.PID, Detail: st.Detail},
	}
	if st.Running {
		res.API = a.probeAPI(cmd.Context(), user)
	}
	if jsonout.Enabled(cmd) {
		return jsonout.Write(cmd.OutOrStdout(), res)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s service %q: %s\n", scope(user), service.DefaultName, describeState(*res.Service))
	if res.API != nil {
		switch {
		case res.API.Status != nil:
			s := res.API.Status
			fmt.Fprintf(out, "daemon: %s to %s as %q, %d tunnel(s), version %s (%s)\n",
				s.State, s.Server, s.ClientName, len(s.Tunnels), s.Version, res.API.Socket)
		default:
			fmt.Fprintf(out, "daemon: no answer on %s: %s\n", res.API.Socket, res.API.Error)
		}
	}
	return nil
}

// probeAPI asks the daemon of the service for its status. A failure is part of the result, not an error.
func (a *app) probeAPI(ctx context.Context, user bool) *apiState {
	socket, err := a.serviceEndpoint(user)
	if err != nil {
		return &apiState{Error: err.Error()}
	}
	st := &apiState{Socket: socket}
	if a.d.dial == nil {
		st.Error = "no local API client in this build"
		return st
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cl := a.d.dial(socket)
	defer cl.Close()
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	s, err := cl.Status(pctx)
	if err != nil {
		st.Error = apiErr(err, socket).Error()
		return st
	}
	st.Status = &s
	return st
}

// userSocketPath is the per-user socket, "" when unknown.
func (d deps) userSocketPath() string {
	if d.userSocket == nil {
		return ""
	}
	return d.userSocket()
}

// configTarget is the config file that `login` and `join` write: --config, else the user's file, and with --system
// the config file of the system service (creating its directory with the right permissions needs elevation).
func (a *app) configTarget(system bool) (string, error) {
	if !system {
		return a.path()
	}
	if a.configPath != "" {
		return "", usageErr(errors.New("--system and --config both name the file to write; use one of them"))
	}
	dir, err := a.systemDir("login --system")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// afterSystemSave hands a system config file to the service account where the OS needs it (Linux).
func (a *app) afterSystemSave(cmd *cobra.Command, system bool, path string) {
	if !system || a.d.fixOwnership == nil {
		return
	}
	if _, err := a.d.fixOwnership(path, ""); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not give the service account access to %s: %v\n", path, err)
	}
}
