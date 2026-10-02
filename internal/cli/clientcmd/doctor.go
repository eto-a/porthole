// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/clientconfig"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/service"
)

// Statuses of a doctor check.
const (
	doctorOK   = "ok"
	doctorWarn = "warn"
	doctorFail = "fail"
)

// doctorDNSTimeout bounds the lookup of the server host name.
const doctorDNSTimeout = 5 * time.Second

// doctorCheck is one line of the report.
type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// doctorReport is the --json document.
type doctorReport struct {
	Checks []doctorCheck `json:"checks"`
	OK     bool          `json:"ok"`
}

// lookupHost resolves a host name to its addresses; the system resolver unless a test replaced it.
func (d deps) lookupHost(ctx context.Context, host string) ([]string, error) {
	if d.lookup != nil {
		return d.lookup(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP.String())
	}
	return out, nil
}

func (a *app) newDoctorCmd() *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose this machine as a porthole client (read-only)",
		Long: "Checks the client config file, the DNS name of the server, the login (connects and authenticates), the local\n" +
			"daemon, the tunnels file and the service, and prints a hint for everything that is not right. It changes\n" +
			"nothing and exits with status 1 when a check fails. With --system it looks at the config file of the system\n" +
			"service instead of your own (reading it may need root or Administrator).",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfgPath, err := a.doctorConfigPath(system)
			if err != nil {
				return usageErr(err)
			}
			rep := a.runDoctor(ctx, cmd, cfgPath, system)
			if jsonout.Enabled(cmd) {
				if err := jsonout.Write(cmd.OutOrStdout(), rep); err != nil {
					return err
				}
			} else {
				writeDoctorTable(cmd.OutOrStdout(), rep)
			}
			if !rep.OK {
				return &exitcode.Error{Code: exitcode.General, Err: errors.New("doctor: some checks failed"), Quiet: true}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "check the config file of the system service instead of your own")
	return cmd
}

// doctorConfigPath is the config file to look at. Unlike configTarget it never creates the system directory.
func (a *app) doctorConfigPath(system bool) (string, error) {
	if !system {
		return a.path()
	}
	if a.configPath != "" {
		return "", errors.New("--system and --config both name the config file; use one of them")
	}
	dir := service.SystemDir()
	if dir == "" {
		return "", errors.New("cannot find the system configuration directory")
	}
	return filepath.Join(dir, "config.yaml"), nil
}

func (a *app) runDoctor(ctx context.Context, cmd *cobra.Command, cfgPath string, system bool) doctorReport {
	cfgCheck, cfg, token := a.checkConfig(cfgPath, system)
	checks := []doctorCheck{cfgCheck}
	daemon, st := a.checkDaemon(ctx)
	if cfgCheck.Status == doctorOK {
		dns := a.checkDNS(ctx, cfg.Server)
		checks = append(checks, dns)
		switch {
		case st != nil:
			// Never log in while a daemon runs: the server keeps one session per client, so a second login with the
			// same token replaces the daemon's session, and a replaced daemon does not reconnect.
			checks = append(checks, serverFromDaemon(st))
		case dns.Status == doctorOK:
			checks = append(checks, a.checkServer(ctx, cmd, cfg.Server, token))
		default:
			checks = append(checks, doctorCheck{
				Name: "server", Status: doctorWarn, Message: "not checked: the server host name does not resolve",
				Hint: dns.Hint,
			})
		}
	}
	checks = append(checks, daemon, a.checkTunnelsFile(filepath.Join(filepath.Dir(cfgPath), tunnelsFileName)), a.checkService())
	return newDoctorReport(checks)
}

func newDoctorReport(checks []doctorCheck) doctorReport {
	rep := doctorReport{Checks: checks, OK: true}
	for _, c := range checks {
		if c.Status == doctorFail {
			rep.OK = false
		}
	}
	return rep
}

func writeDoctorTable(w io.Writer, rep doctorReport) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tSTATUS\tMESSAGE")
	for _, c := range rep.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, c.Status, c.Message)
	}
	_ = tw.Flush()
	var hints []doctorCheck
	for _, c := range rep.Checks {
		if c.Hint != "" && c.Status != doctorOK {
			hints = append(hints, c)
		}
	}
	if len(hints) > 0 {
		fmt.Fprintln(w)
		for _, c := range hints {
			fmt.Fprintf(w, "%s: %s\n", c.Name, c.Hint)
		}
	}
}

const joinHint = "run `porthole join <link>` (a link from the server operator) or `porthole login <server-url> <token>`"

// checkConfig reads the config file without printing the token. On success it returns the file and the token.
func (a *app) checkConfig(path string, system bool) (doctorCheck, fileConfig, string) {
	fail := func(msg, hint string) (doctorCheck, fileConfig, string) {
		return doctorCheck{Name: "config", Status: doctorFail, Message: msg, Hint: hint}, fileConfig{}, ""
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return fail("no config file at "+path, joinHint)
	} else if err != nil {
		return fail(err.Error(), permissionHint(err, system))
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return fail(err.Error(), permissionHint(err, system))
	}
	token, err := cfg.resolveToken(path)
	if err != nil {
		return fail(err.Error(), permissionHint(err, system))
	}
	if cfg.Server == "" {
		return fail(path+" has no server URL", joinHint)
	}
	if _, err := client.ConnectURL(cfg.Server); err != nil {
		return fail(err.Error(), "fix the server URL in "+path+" or "+joinHint)
	}
	if token == "" {
		return fail(path+" has neither token nor token_file", joinHint)
	}
	if _, err := auth.Parse(token); err != nil {
		return fail("the token in "+path+" is malformed (expected ph_<id>_<secret>)", joinHint)
	}
	source := "token"
	if cfg.TokenFile != "" {
		source = "token_file"
	}
	return doctorCheck{
		Name: "config", Status: doctorOK, Message: fmt.Sprintf("%s: server %s, %s set", path, cfg.Server, source),
	}, cfg, token
}

func permissionHint(err error, system bool) string {
	if errors.Is(err, fs.ErrPermission) {
		if system {
			return elevationHint(runtime.GOOS, "doctor --system")
		}
		return "the file belongs to another user; run doctor as the user who owns it"
	}
	return "fix or remove the file, then " + joinHint
}

func (a *app) checkDNS(ctx context.Context, server string) doctorCheck {
	u, err := url.Parse(server)
	if err != nil {
		return doctorCheck{Name: "dns", Status: doctorFail, Message: err.Error(), Hint: "fix the server URL"}
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err == nil {
		return doctorCheck{Name: "dns", Status: doctorOK, Message: host + " is an IP address"}
	}
	ctx, cancel := context.WithTimeout(ctx, doctorDNSTimeout)
	defer cancel()
	addrs, err := a.d.lookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		msg := "no addresses"
		if err != nil {
			msg = err.Error()
		}
		return doctorCheck{
			Name: "dns", Status: doctorFail, Message: fmt.Sprintf("cannot resolve %s: %s", host, msg),
			Hint: "check the server URL for typos, your network and DNS settings",
		}
	}
	return doctorCheck{Name: "dns", Status: doctorOK, Message: fmt.Sprintf("%s -> %s", host, strings.Join(addrs, ", "))}
}

func (a *app) checkServer(ctx context.Context, cmd *cobra.Command, server, token string) doctorCheck {
	if a.d.check == nil {
		return doctorCheck{Name: "server", Status: doctorWarn, Message: "the server check is not available in this build"}
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	res, err := a.d.check(ctx, client.Options{ServerURL: server, Token: token, Version: a.version, Logger: a.logger(cmd)})
	if err == nil {
		return doctorCheck{
			Name: "server", Status: doctorOK,
			Message: fmt.Sprintf("logged in as %q (server version %s)", res.ClientName, res.ServerVersion),
		}
	}
	var perr *proto.Error
	if errors.As(err, &perr) {
		c := doctorCheck{Name: "server", Status: doctorFail, Message: explain(err).Error()}
		switch perr.Code {
		case proto.CodeUnauthorized, proto.CodeTokenRevoked, proto.CodeTokenExpired:
			c.Hint = "the token was revoked, has expired or is wrong: ask the server operator for a new link and run `porthole join <link>` again"
		case proto.CodeUnsupportedVersion:
			c.Hint = "upgrade porthole to the version the server supports"
		default:
			c.Hint = "the server refused the login; see the message above"
		}
		return c
	}
	c := doctorCheck{Name: "server", Status: doctorFail, Message: err.Error()}
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns) && dns.IsNotFound:
		c.Hint = "the server host name does not resolve; check the server URL for typos"
	case client.IsTLSVerifyError(err):
		c.Hint = "the server certificate could not be verified: check the host name in the URL and the server's certificate"
	case errors.Is(err, context.DeadlineExceeded):
		c.Hint = "the server did not answer in time: check that portholed is running and that no firewall or proxy blocks it"
	default:
		c.Hint = "check the server URL, that portholed is running, and that no firewall or proxy blocks the connection"
	}
	return c
}

// serverFromDaemon reports the server check from what a running daemon knows, without a login of our own.
func serverFromDaemon(st *localapi.Status) doctorCheck {
	if st.State == localapi.StateConnected {
		return doctorCheck{
			Name: "server", Status: doctorOK,
			Message: fmt.Sprintf("the daemon is connected to %s as %q (no second login: it would replace the daemon's session)", st.Server, st.ClientName),
		}
	}
	c := doctorCheck{
		Name: "server", Status: doctorWarn,
		Message: fmt.Sprintf("the daemon is %s, not connected to %s", st.State, st.Server),
		Hint:    "see `porthole status`; the daemon keeps retrying",
	}
	if st.LastError != "" {
		c.Message += ": " + st.LastError
	}
	return c
}

// checkDaemon reports the local daemon; the status is non-nil when one answered.
func (a *app) checkDaemon(ctx context.Context) (doctorCheck, *localapi.Status) {
	const name = "daemon"
	if a.d.dial == nil {
		return doctorCheck{Name: name, Status: doctorOK, Message: "no local API client in this build"}, nil
	}
	cl, socket, err := a.findDaemon(ctx)
	if err != nil {
		var denied *deniedError
		switch {
		case isNoDaemon(err):
			return doctorCheck{Name: name, Status: doctorOK, Message: "no daemon (tunnels run in the foreground)"}, nil
		case errors.As(err, &denied):
			return doctorCheck{
				Name: name, Status: doctorWarn,
				Message: fmt.Sprintf("permission denied on the daemon socket %s", denied.path), Hint: accessAdvice(runtime.GOOS),
			}, nil
		default:
			return doctorCheck{Name: name, Status: doctorWarn, Message: err.Error(), Hint: "restart the daemon"}, nil
		}
	}
	defer cl.Close()
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	st, err := cl.Status(pctx)
	if err != nil {
		return doctorCheck{Name: name, Status: doctorWarn, Message: apiErr(err, socket).Error(), Hint: "restart the daemon"}, nil
	}
	c := doctorCheck{
		Name: name, Status: doctorOK,
		Message: fmt.Sprintf("running, version %s, %d tunnel(s), %s (%s)", st.Version, len(st.Tunnels), st.State, socket),
	}
	if hint := versionSkew(&apiState{Status: &st}, a.version); hint != "" {
		c.Status = doctorWarn
		c.Message = fmt.Sprintf("running porthole %s, but this command is %s", st.Version, a.version)
		c.Hint = hint
	}
	return c, &st
}

func (a *app) checkTunnelsFile(path string) doctorCheck {
	const name = "tunnels_file"
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return doctorCheck{Name: name, Status: doctorOK, Message: "none"}
	} else if err != nil {
		return doctorCheck{Name: name, Status: doctorFail, Message: err.Error(), Hint: permissionHint(err, false)}
	}
	f, err := clientconfig.Load(path)
	if err != nil {
		return doctorCheck{Name: name, Status: doctorFail, Message: err.Error(), Hint: "fix the file, then run `porthole reload` if a daemon is running"}
	}
	return doctorCheck{Name: name, Status: doctorOK, Message: fmt.Sprintf("%s: %d tunnel(s)", path, len(f.Tunnels))}
}

// checkService reports the system service and, when there is one, the user service.
func (a *app) checkService() doctorCheck {
	const name = "service"
	if a.d.newService == nil {
		return doctorCheck{Name: name, Status: doctorOK, Message: "services are not available in this build"}
	}
	c := doctorCheck{Name: name, Status: doctorOK}
	var parts []string
	for _, user := range []bool{false, true} {
		m, err := a.d.newService(user)
		if errors.Is(err, service.ErrUnsupported) {
			if !user {
				return doctorCheck{Name: name, Status: doctorOK, Message: "no service manager on this system"}
			}
			continue
		}
		if err != nil {
			c.Status = doctorWarn
			parts = append(parts, fmt.Sprintf("%s service: %v", scope(user), err))
			continue
		}
		st, err := m.Status(service.DefaultName)
		if err != nil {
			c.Status = doctorWarn
			parts = append(parts, fmt.Sprintf("%s service: %v", scope(user), err))
			continue
		}
		if user && !st.Installed {
			continue
		}
		state := serviceState{Installed: st.Installed, Running: st.Running, PID: st.PID, Detail: st.Detail}
		parts = append(parts, fmt.Sprintf("%s service %s", scope(user), describeState(state)))
		if st.Installed && !st.Running {
			c.Status = doctorWarn
			c.Hint = "start it with `porthole service start` (add --user for the user service)"
		}
	}
	c.Message = strings.Join(parts, "; ")
	return c
}
