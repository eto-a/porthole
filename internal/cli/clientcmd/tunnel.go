// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

// connFlags are the per-command overrides of the stored credentials.
type connFlags struct {
	server      string
	token       string
	maxAttempts int
}

func (f *connFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.server, "server", "", "server URL (overrides $"+envServer+" and the config file; only with --no-daemon)")
	cmd.Flags().StringVar(&f.token, "token", "", "token (overrides $"+envToken+" and the config file; only with --no-daemon)")
	cmd.Flags().IntVar(&f.maxAttempts, "max-initial-attempts", client.DefaultMaxInitialAttempts,
		"give up if no connection to the server could be established after this many attempts (0 = retry forever); "+
			"once connected, the client always reconnects")
}

// credsFrom is where the credentials of a command come from.
type credsFrom struct {
	// server is the server URL given by flag or environment; configServer is the one of the config file. The caller
	// picks (the tunnels file sits in between for `start` and the daemon). Either may be empty.
	server, configServer string
	token                string
}

// resolveCreds resolves the server and the token: flag, then environment, then the config file (where the token
// comes from `token` or `token_file`). The config file is read only if something is still missing.
func (a *app) resolveCreds(f *connFlags) (credsFrom, error) {
	c := credsFrom{server: f.server, token: f.token}
	if c.server == "" {
		c.server = a.d.getenv(envServer)
	}
	if c.token == "" {
		c.token = a.d.getenv(envToken)
	}
	if c.server == "" || c.token == "" {
		path, err := a.path()
		if err != nil {
			return credsFrom{}, err
		}
		cfg, err := loadConfig(path)
		if err != nil {
			return credsFrom{}, err
		}
		c.configServer = cfg.Server
		if c.token == "" {
			if c.token, err = cfg.resolveToken(path); err != nil {
				return credsFrom{}, err
			}
		}
	}
	if c.token != "" {
		if _, err := auth.Parse(c.token); err != nil {
			return credsFrom{}, errors.New("the configured token is malformed (expected ph_<id>_<secret>); run `porthole login` with a valid token")
		}
	}
	return c, nil
}

// credentials resolves server and token: flag, then environment, then config file.
func (a *app) credentials(f *connFlags) (server, token string, err error) {
	c, err := a.resolveCreds(f)
	if err != nil {
		return "", "", configErr(err)
	}
	server = c.server
	if server == "" {
		server = c.configServer
	}
	return a.checkCreds(server, c.token)
}

// checkCreds verifies that server and token are set and well-formed.
func (a *app) checkCreds(server, token string) (string, string, error) {
	if server == "" || token == "" {
		return "", "", configErr(fmt.Errorf("no server or token configured: run `porthole login <server-url> <token>`, "+
			"or set %s and %s", envServer, envToken))
	}
	if _, err := client.ConnectURL(server); err != nil {
		return "", "", configErr(err)
	}
	if _, err := auth.Parse(token); err != nil {
		return "", "", configErr(errors.New("the configured token is malformed (expected ph_<id>_<secret>); run `porthole login` with a valid token"))
	}
	return server, token, nil
}

// routeFlags choose between the daemon and an in-process client for `porthole http|tcp|ssh`.
type routeFlags struct {
	noDaemon bool
	daemon   bool
	detach   bool
}

func (f *routeFlags) add(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.noDaemon, "no-daemon", false, "run in this process even if a daemon is running")
	cmd.Flags().BoolVar(&f.daemon, "daemon", false, "require a running daemon (fail instead of running in this process)")
	cmd.Flags().BoolVar(&f.detach, "detach", false,
		"add the tunnel to the daemon and exit; it stays until `porthole close <name>` or a daemon restart (implies --daemon)")
	cmd.MarkFlagsMutuallyExclusive("daemon", "no-daemon")
	cmd.MarkFlagsMutuallyExclusive("detach", "no-daemon")
}

// tunnelRequest is one tunnel as the http, tcp and ssh commands describe it.
type tunnelRequest struct {
	typ        string // localapi.TypeHTTP, TypeTCP or TypeSSH
	name       string
	addr       string // "host:port", already normalized
	remotePort int
	sshUser    string // non-empty for `porthole ssh`: print the ssh command line
	private    bool   // ssh only: the gateway requires a porthole token
	inspect    bool   // http only: the server stores request and response bodies for the inspector
	publicPort bool   // ssh only: a public TCP port instead of the gateway (v0.1 behaviour)
}

func (r tunnelRequest) spec() client.TunnelSpec {
	kind := proto.KindTCP
	switch {
	case r.typ == localapi.TypeHTTP:
		kind = proto.KindHTTP
	case r.typ == localapi.TypeSSH && !r.publicPort:
		kind = proto.KindSSH
	}
	return client.TunnelSpec{Kind: kind, Name: r.name, LocalAddr: r.addr, RemotePort: r.remotePort, Private: r.private, Inspect: r.inspect}
}

func (r tunnelRequest) apiRequest() localapi.AddTunnelRequest {
	return localapi.AddTunnelRequest{
		Type: r.typ, Name: r.name, Addr: r.addr, RemotePort: r.remotePort, Private: r.private, Inspect: r.inspect, PublicPort: r.publicPort,
	}
}

// canFallback reports whether a server that refuses the ssh kind may be retried with a public TCP port: only the
// default `porthole ssh`, never a --private one (it must not become public) or an explicit --public-port.
func (r tunnelRequest) canFallback() bool {
	return r.typ == localapi.TypeSSH && !r.private && !r.publicPort
}

// sshHint carries what printEvent needs to print the ssh command of an ssh tunnel.
type sshHint struct {
	user   string
	client string // client name; learned from the connected event or the daemon status
}

func (h *sshHint) enabled() bool { return h != nil && h.user != "" }

func (r tunnelRequest) hint() *sshHint {
	if r.sshUser == "" {
		return nil
	}
	return &sshHint{user: r.sshUser}
}

func (a *app) newHTTPCmd() *cobra.Command {
	var cf connFlags
	var inspect bool
	var rf routeFlags
	var name string
	cmd := &cobra.Command{
		Use:   "http <port|host:port>",
		Short: "Expose a local HTTP service",
		Long: "Expose a local HTTP service. A bare port means 127.0.0.1:<port>.\n\n" +
			"If a porthole daemon is running the tunnel is added to it and removed again when this command ends.",
		Example: "  porthole http 8080\n" +
			"  porthole http 192.168.1.10:3000 --name blog\n" +
			"  porthole http 8080 --inspect",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := parseTarget(args[0])
			if err != nil {
				return usageErr(err)
			}
			return a.runTunnel(cmd, &cf, &rf, tunnelRequest{typ: localapi.TypeHTTP, name: name, addr: target, inspect: inspect})
		},
	}
	cf.add(cmd)
	rf.add(cmd)
	cmd.Flags().StringVar(&name, "name", "", "tunnel name (default http-<port>)")
	cmd.Flags().BoolVar(&inspect, "inspect", false, "store request and response bodies (up to 64 KiB each) and headers on the server for inspection and replay; Authorization and Cookie headers are masked")
	return cmd
}

func (a *app) newTCPCmd() *cobra.Command {
	var cf connFlags
	var rf routeFlags
	var name string
	var remotePort int
	cmd := &cobra.Command{
		Use:   "tcp <port|host:port>",
		Short: "Expose a local TCP service",
		Long: "Expose a local TCP service on a public port of the server. A bare port means 127.0.0.1:<port>.\n\n" +
			"If a porthole daemon is running the tunnel is added to it and removed again when this command ends.",
		Example: "  porthole tcp 5432\n" +
			"  porthole tcp 5432 --remote-port 20017",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := parseTarget(args[0])
			if err != nil {
				return usageErr(err)
			}
			if cmd.Flags().Changed("remote-port") {
				if _, err := parsePort(fmt.Sprint(remotePort)); err != nil {
					return usageErr(fmt.Errorf("--remote-port: %w", err))
				}
			}
			return a.runTunnel(cmd, &cf, &rf, tunnelRequest{typ: localapi.TypeTCP, name: name, addr: target, remotePort: remotePort})
		},
	}
	cf.add(cmd)
	rf.add(cmd)
	cmd.Flags().StringVar(&name, "name", "", "tunnel name (default tcp-<port>)")
	cmd.Flags().IntVar(&remotePort, "remote-port", 0, "request this public port (default: any free port in the server's range)")
	return cmd
}

func (a *app) newSSHCmd() *cobra.Command {
	var cf connFlags
	var rf routeFlags
	var name, userName string
	var localPort, remotePort int
	var private, publicPort bool
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Expose the local ssh server",
		Long: "Expose the local ssh server and print the ssh command to reach it.\n\n" +
			"By default the server's SSH gateway is the jump host: no public port is opened, and others connect with\n" +
			"`ssh -J <gateway> <user>@<client>`. --private makes the gateway ask for a porthole token first.\n" +
			"--public-port keeps the older mode: a public TCP port of the server (`ssh -p <port> <user>@<server>`).\n" +
			"If the server has no SSH gateway, a plain `porthole ssh` falls back to a public port with a warning.\n\n" +
			"If a porthole daemon is running the tunnel is added to it and removed again when this command ends.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := parsePort(fmt.Sprint(localPort)); err != nil {
				return usageErr(fmt.Errorf("--local-port: %w", err))
			}
			target, err := parseTarget(fmt.Sprint(localPort))
			if err != nil {
				return usageErr(err)
			}
			if cmd.Flags().Changed("remote-port") {
				if _, err := parsePort(fmt.Sprint(remotePort)); err != nil {
					return usageErr(fmt.Errorf("--remote-port: %w", err))
				}
				if !publicPort {
					return usageErr(errors.New("--remote-port needs --public-port: through the gateway the tunnel has no public port"))
				}
			}
			if userName == "" {
				userName = a.d.currentUser()
			}
			return a.runTunnel(cmd, &cf, &rf, tunnelRequest{
				typ: localapi.TypeSSH, name: name, addr: target, sshUser: userName,
				remotePort: remotePort, private: private, publicPort: publicPort,
			})
		},
	}
	cf.add(cmd)
	rf.add(cmd)
	cmd.Flags().IntVar(&localPort, "local-port", 22, "local ssh port")
	cmd.Flags().StringVar(&userName, "user", "", "user name for the printed ssh command (default: current user)")
	cmd.Flags().StringVar(&name, "name", "ssh", "tunnel name")
	cmd.Flags().BoolVar(&private, "private", false, "require a porthole token at the SSH gateway; never falls back to a public port")
	cmd.Flags().BoolVar(&publicPort, "public-port", false, "open a public TCP port instead of using the SSH gateway")
	cmd.Flags().IntVar(&remotePort, "remote-port", 0, "with --public-port: request this public port")
	cmd.MarkFlagsMutuallyExclusive("private", "public-port")
	return cmd
}

// signalContext returns the command's context cancelled by Ctrl-C and SIGTERM.
func signalContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

// runTunnel runs one tunnel in the foreground until interrupted: through the daemon if one is reachable (and the
// flags allow it), otherwise in this process.
func (a *app) runTunnel(cmd *cobra.Command, cf *connFlags, rf *routeFlags, tr tunnelRequest) error {
	ctx, stop := signalContext(cmd)
	defer stop()

	err := a.runTunnelOnce(ctx, cmd, cf, rf, tr)
	var perr *proto.Error
	if err != nil && tr.canFallback() && errors.As(err, &perr) && perr.Code == proto.CodeInvalidRequest {
		// An old server answers invalid_request to the unknown kind "ssh", a new one without the gateway says so.
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: the server does not offer the SSH gateway (%s); "+
			"falling back to a public TCP port. Use --public-port to choose this on purpose.\n", perr.Message)
		tr.publicPort = true
		return a.runTunnelOnce(ctx, cmd, cf, rf, tr)
	}
	return err
}

// runTunnelOnce routes one tunnel request, see runTunnel.
func (a *app) runTunnelOnce(ctx context.Context, cmd *cobra.Command, cf *connFlags, rf *routeFlags, tr tunnelRequest) error {
	if rf.noDaemon {
		return a.runStandalone(ctx, cmd, cf, tr)
	}
	cl, path, err := a.findDaemon(ctx)
	switch {
	case err == nil:
		defer cl.Close()
		if err := rejectCredentialFlags(cmd, path); err != nil {
			return err
		}
		if rf.detach {
			return a.detachTunnel(ctx, cmd, cl, path, tr)
		}
		return a.attachTunnel(ctx, cmd, cl, path, tr)
	case isNoDaemon(err):
		// An explicit --socket that nobody answers on is a mistake, not a reason to quietly run standalone.
		if rf.daemon || rf.detach || a.socket != "" {
			return err
		}
		return a.runStandalone(ctx, cmd, cf, tr)
	default:
		return err
	}
}

// rejectCredentialFlags fails if flags that only configure an in-process client were given while a daemon, which has
// its own credentials, is going to run the tunnel.
func rejectCredentialFlags(cmd *cobra.Command, socket string) error {
	var given []string
	for _, name := range []string{"server", "token", "max-initial-attempts"} {
		if cmd.Flags().Changed(name) {
			given = append(given, "--"+name)
		}
	}
	if len(given) == 0 {
		return nil
	}
	return usageErr(fmt.Errorf("%s configure a standalone client and cannot be combined with the daemon at %s, which has its own "+
		"server and token; drop them or use --no-daemon to run in this process", strings.Join(given, ", "), socket))
}

// runStandalone runs the tunnel in this process, as porthole did before the daemon existed.
func (a *app) runStandalone(ctx context.Context, cmd *cobra.Command, cf *connFlags, tr tunnelRequest) error {
	server, token, err := a.credentials(cf)
	if err != nil {
		return err
	}
	hint := tr.hint()
	sink := eventSink(cmd, hint, false)
	err = a.d.run(ctx, client.Options{
		ServerURL: server,
		Token:     token,
		Tunnels:   []client.TunnelSpec{tr.spec()},
		Version:   a.version,
		Logger:    a.logger(cmd),
		OnEvent:   sink,

		MaxInitialAttempts: max(cf.maxAttempts, 0),
	})
	if err != nil {
		return explain(err)
	}
	return nil
}

// printEvent renders a client event for the terminal. Status goes to out, trouble to errOut.
func printEvent(out, errOut io.Writer, e client.Event, hint *sshHint) {
	switch e := e.(type) {
	case client.Connected:
		fmt.Fprintf(out, "connected as %s\n", e.ClientName)
		if hint != nil {
			hint.client = e.ClientName
		}
	case client.TunnelReady:
		if e.SSHJump != "" {
			fmt.Fprintf(out, "ssh tunnel %s via %s -> %s\n", e.Name, e.SSHJump, e.Spec.LocalAddr)
			if hint.enabled() {
				printSSHJump(out, hint, e)
			}
			return
		}
		fmt.Fprintf(out, "%s -> %s\n", e.PublicURL, e.Spec.LocalAddr)
		if hint.enabled() {
			if cmdline, ok := sshCommand(e.PublicURL, hint.user); ok {
				fmt.Fprintf(out, "  %s\n", cmdline)
			}
		}
	case client.TunnelClosed:
		fmt.Fprintf(errOut, "tunnel %s closed: %s\n", e.Name, e.Reason)
	case client.Disconnected:
		secs := max(1, int(math.Ceil(e.RetryIn.Seconds())))
		if e.Attempt > 0 {
			limit := "unlimited"
			if e.MaxAttempts > 0 {
				limit = fmt.Sprint(e.MaxAttempts)
			}
			fmt.Fprintf(errOut, "cannot connect (attempt %d of %s), retrying in %ds: %v\n", e.Attempt, limit, secs, e.Err)
			return
		}
		fmt.Fprintf(errOut, "reconnecting in %ds: %v\n", secs, e.Err)
	}
}

// sshTarget is the host name the gateway resolves to the tunnel: the client name for the default tunnel "ssh",
// otherwise "<tunnel>-<client>" (ADR 0003).
func sshTarget(tunnelName, clientName string) string {
	if clientName == "" {
		clientName = "<client>"
	}
	if tunnelName == "ssh" || tunnelName == "" {
		return clientName
	}
	return tunnelName + "-" + clientName
}

// printSSHJump prints the ready-to-use `ssh -J` command and the ~/.ssh/config equivalent.
func printSSHJump(out io.Writer, h *sshHint, e client.TunnelReady) {
	target := sshTarget(e.Name, h.client)
	jump := e.SSHJump
	if e.Spec.Private {
		// OpenSSH always tries "none" first; the gateway refuses it, and so asks for a password, only for user "token".
		jump = "token@" + jump
	}
	fmt.Fprintf(out, "  ssh -J %s %s@%s\n", jump, h.user, target)
	fmt.Fprintf(out, "  or once in ~/.ssh/config:  Host %s  /  ProxyJump %s\n", target, jump)
	if e.Spec.Private {
		fmt.Fprintln(out, "  private tunnel: the gateway asks for a porthole token as the password before the usual ssh prompt")
	}
}

// sshCommand builds `ssh -p <port> <user>@<host>` from a tcp://host:port public URL.
func sshCommand(publicURL, user string) (string, bool) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Hostname() == "" || u.Port() == "" {
		return "", false
	}
	return fmt.Sprintf("ssh -p %s %s@%s", u.Port(), user, u.Hostname()), true
}

// explainedError is an error with a user-oriented message that still unwraps to the original.
type explainedError struct {
	msg string
	err error
}

func (e *explainedError) Error() string { return e.msg }
func (e *explainedError) Unwrap() error { return e.err }

// explain rewrites well-known server errors into actionable messages.
func explain(err error) error {
	var ice *client.InitialConnectError
	if errors.As(err, &ice) {
		return &explainedError{msg: initialConnectMessage(ice), err: err}
	}
	var perr *proto.Error
	if !errors.As(err, &perr) {
		return err
	}
	detail := perr.Code
	if perr.Message != "" {
		detail += ": " + perr.Message
	}
	var msg string
	switch perr.Code {
	case proto.CodeUnauthorized, proto.CodeTokenRevoked:
		msg = fmt.Sprintf("token rejected by server (%s); run `porthole login` with a valid token", detail)
	case proto.CodeTokenExpired:
		msg = fmt.Sprintf("token expired (%s); get a new token from the server operator and run `porthole login`", detail)
	case proto.CodeUnsupportedVersion:
		msg = fmt.Sprintf("server does not support this client version (%s); upgrade porthole", detail)
	case proto.CodeSessionReplaced:
		msg = fmt.Sprintf("another porthole process logged in with the same token (%s); each machine needs its own token", detail)
	case proto.CodeNameTaken:
		msg = fmt.Sprintf("tunnel name already in use (%s); choose another one with --name", detail)
	case proto.CodeForbidden:
		msg = fmt.Sprintf("server refused the tunnel (%s); this token may not be allowed to create it", detail)
	case proto.CodePortUnavailable:
		msg = fmt.Sprintf("requested port is not available (%s); try another --remote-port or omit it", detail)
	default:
		return err
	}
	return &explainedError{msg: msg, err: err}
}

// initialConnectMessage turns a failed first connection into a message with things to check.
func initialConnectMessage(e *client.InitialConnectError) string {
	var hint string
	var dns *net.DNSError
	switch {
	case errors.As(e.Err, &dns) && dns.IsNotFound:
		hint = "the server host name does not resolve; check the server URL for typos"
	case client.IsTLSVerifyError(e.Err):
		hint = "the server certificate could not be verified; check that the URL uses the right host name " +
			"and that the server has a valid certificate"
	default:
		hint = "check the server URL (see `porthole login`), that portholed is running, " +
			"and that no firewall or proxy blocks the connection"
	}
	return fmt.Sprintf("could not connect to the server after %d attempt(s): %v\n%s; "+
		"use --max-initial-attempts 0 to keep retrying", e.Attempts, e.Err, hint)
}
