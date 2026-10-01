// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/clientconfig"
	"github.com/eto-a/porthole/internal/daemon"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/service"
)

const (
	tunnelsFileName = "tunnels.yaml"

	systemSocketMode os.FileMode = 0o660 // the system daemon's socket is shared with the porthole-client group
	userSocketMode   os.FileMode = 0o600
)

// tunnelsPath returns the tunnels file: the flag if given, else tunnels.yaml next to the config file.
func (a *app) tunnelsPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	cfg, err := a.path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), tunnelsFileName), nil
}

// daemonSocket returns the socket `porthole daemon` creates: --socket, then $PORTHOLE_SOCKET, then the user socket.
func (a *app) daemonSocket() (string, error) {
	switch {
	case a.socket != "":
		return a.socket, nil
	case a.d.getenv(envSocket) != "":
		return a.d.getenv(envSocket), nil
	case a.d.userSocket != nil && a.d.userSocket() != "":
		return a.d.userSocket(), nil
	default:
		return "", errors.New("cannot determine the daemon socket path; use --socket or set $" + envSocket)
	}
}

func (a *app) newDaemonCmd() *cobra.Command {
	var tunnelsFlag string
	var allow []string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the client daemon: keep the tunnels of the tunnels file up",
		Long: "Run the porthole client daemon. It holds one session to the server, keeps the tunnels defined in the tunnels " +
			"file registered (reconnecting forever), and serves a local API on a unix socket (a named pipe on Windows) that " +
			"`porthole status`, `reload`, `close` and the tunnel commands use. `porthole reload` and SIGHUP (on Windows " +
			"`sc control porthole paramchange`) re-read the tunnels file.\n\n" +
			"The server and token come from the config file (see `porthole login`), $" + envServer + " and $" + envToken + ". " +
			"A broken configuration makes the daemon exit with status " + fmt.Sprint(ExitConfig) + ".\n\n" +
			"Started by the Windows service control manager it runs as the service (see `porthole service`) and logs to " +
			"%ProgramData%\\porthole\\logs\\porthole.log.",
		Example: "  porthole daemon\n" +
			"  porthole daemon --config /etc/porthole/config.yaml --tunnels /etc/porthole/tunnels.yaml \\\n" +
			"      --socket /run/porthole/porthole.sock",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.runDaemonCmd(cmd, tunnelsFlag, allow) },
	}
	cmd.Flags().StringVar(&tunnelsFlag, "tunnels", "", "tunnels file (default: tunnels.yaml next to the config file)")
	cmd.Flags().StringArrayVar(&allow, "allow", nil,
		"user or group admitted to the system named pipe (Windows only, with the system socket); repeatable")
	return cmd
}

// daemonOptions resolves everything `porthole daemon` needs. Its errors are already configuration errors (exit 78).
func (a *app) daemonOptions(tunnelsFlag string, allow []string, logger *slog.Logger) (daemon.Options, error) {
	tunnels, err := a.tunnelsPath(tunnelsFlag)
	if err != nil {
		return daemon.Options{}, configErr(err)
	}
	socket, err := a.daemonSocket()
	if err != nil {
		return daemon.Options{}, configErr(err)
	}
	creds, err := a.resolveCreds(&connFlags{})
	if err != nil {
		return daemon.Options{}, configErr(err)
	}
	if creds.token == "" {
		return daemon.Options{}, configErr(fmt.Errorf("no token configured: run `porthole login <server-url> <token>`, or set %s", envToken))
	}
	mode := userSocketMode
	if socket == localapi.SystemSocketPath {
		mode = systemSocketMode
	}
	return daemon.Options{
		ServerURL:    creds.server,
		ConfigServer: creds.configServer,
		Token:        creds.token,
		TunnelsPath:  tunnels,
		SocketPath:   socket,
		SocketMode:   mode,
		SocketAllow:  allow,
		Version:      a.version,
		Logger:       logger,
	}, nil
}

func (a *app) runDaemonCmd(cmd *cobra.Command, tunnelsFlag string, allow []string) error {
	if a.d.isService != nil {
		inService, err := a.d.isService()
		if err != nil {
			return err
		}
		if inService {
			return a.runDaemonService(tunnelsFlag, allow)
		}
	}
	opts, err := a.daemonOptions(tunnelsFlag, allow, a.daemonLogger(cmd))
	if err != nil {
		return err
	}
	ctx, stop := signalContext(cmd)
	defer stop()
	return daemonResult(a.d.runDaemon(ctx, opts))
}

// runDaemonService runs the daemon inside the Windows service control manager: the log goes to a file, the service
// is Running once the daemon reports READY, ParamChange reloads the tunnels file and Stop cancels the context. A
// configuration error is detected inside the service, so that the manager sees a service that failed to start (with
// the reason in the log and the event log) instead of one that never answered.
func (a *app) runDaemonService(tunnelsFlag string, allow []string) error {
	if a.d.runService == nil {
		return errors.New("running as a service is not available in this build")
	}
	logger, closeLog := a.serviceLogger()
	defer closeLog()
	return a.d.runService(service.DefaultName, func(ctx context.Context, ready func(), reload <-chan struct{}) error {
		opts, err := a.daemonOptions(tunnelsFlag, allow, logger)
		if err != nil {
			logger.Error("invalid configuration", "err", err)
			return err
		}
		opts.Reload = reload
		opts.Notify = func(state string) (bool, error) {
			if state == localapi.NotifyReady {
				ready()
			}
			return true, nil
		}
		err = daemonResult(a.d.runDaemon(ctx, opts))
		if err != nil {
			logger.Error("daemon failed", "err", err)
		}
		return err
	})
}

// serviceLogger logs to %ProgramData%\porthole\logs\porthole.log (10 MiB, one .1 copy), or to stderr if the file
// cannot be opened (the service then has no console, but nothing else is lost).
func (a *app) serviceLogger() (*slog.Logger, func()) {
	level := slog.LevelInfo
	if a.verbose {
		level = slog.LevelDebug
	}
	hopts := &slog.HandlerOptions{Level: level}
	f, err := openRotatingFile(serviceLogPath(a.d.getenv), maxLogSize)
	if err != nil {
		l := slog.New(slog.NewTextHandler(os.Stderr, hopts))
		l.Warn("cannot open the service log file, logging to stderr", "err", err)
		return l, func() {}
	}
	return slog.New(slog.NewTextHandler(f, hopts)), func() { _ = f.Close() }
}

// daemonResult maps the result of the daemon to the command's error: a configuration problem exits with status 78.
func daemonResult(err error) error {
	if err == nil {
		return nil
	}
	err = explain(err)
	var ce *daemon.ConfigError
	if errors.As(err, &ce) {
		return configErr(err)
	}
	return err
}

// daemonLogger logs at info level (a service wants its lifecycle in the journal); --verbose adds debug.
func (a *app) daemonLogger(cmd *cobra.Command) *slog.Logger {
	level := slog.LevelInfo
	if a.verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if jsonout.Enabled(cmd) { // structured logs on stderr; stdout stays empty
		return slog.New(slog.NewJSONHandler(cmd.ErrOrStderr(), opts))
	}
	return slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), opts))
}

func (a *app) newStartCmd() *cobra.Command {
	var cf connFlags
	var tunnelsFlag string
	cmd := &cobra.Command{
		Use:   "start [name...]",
		Short: "Run the tunnels of the tunnels file in the foreground",
		Long: "Run the tunnels of the tunnels file in this process, without a daemon, until interrupted. Without names " +
			"every enabled tunnel is started; with names exactly those tunnels, enabled or not.\n\n" +
			"The server is taken from --server, $" + envServer + ", the `server` key of the tunnels file, or the config file, " +
			"in this order.",
		Example: "  porthole start\n" +
			"  porthole start blog db --tunnels ./tunnels.yaml",
		RunE: func(cmd *cobra.Command, names []string) error { return a.runStart(cmd, &cf, tunnelsFlag, names) },
	}
	cf.add(cmd)
	cmd.Flags().StringVar(&tunnelsFlag, "tunnels", "", "tunnels file (default: tunnels.yaml next to the config file)")
	return cmd
}

func (a *app) runStart(cmd *cobra.Command, cf *connFlags, tunnelsFlag string, names []string) error {
	path, err := a.tunnelsPath(tunnelsFlag)
	if err != nil {
		return err
	}
	file, err := clientconfig.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return configErr(fmt.Errorf("tunnels file %s does not exist; create it or pass --tunnels", path))
	}
	if err != nil {
		return configErr(err)
	}
	specs, err := file.Specs(names...)
	if err != nil {
		return configErr(err)
	}
	if len(specs) == 0 {
		return configErr(fmt.Errorf("%s defines no enabled tunnels; add some, or name the tunnels to start", path))
	}
	creds, err := a.resolveCreds(cf)
	if err != nil {
		return configErr(err)
	}
	server := creds.server
	if server == "" {
		server = file.Server
	}
	if server == "" {
		server = creds.configServer
	}
	server, token, err := a.checkCreds(server, creds.token)
	if err != nil {
		return err
	}

	ctx, stop := signalContext(cmd)
	defer stop()
	errOut := cmd.ErrOrStderr()
	warnPlaintext(cmd, server)
	// A daemon that uses the same token would be replaced by this session and then evict it again.
	if _, socket, err := a.findDaemon(ctx); err == nil {
		fmt.Fprintf(errOut, "note: a porthole daemon is running (%s); if it uses the same token, this session replaces "+
			"its connection to the server. Use `porthole reload` to change the daemon's tunnels instead.\n", socket)
	}

	err = a.d.run(ctx, client.Options{
		ServerURL:          server,
		Token:              token,
		Tunnels:            specs,
		Version:            a.version,
		Logger:             a.logger(cmd),
		OnEvent:            eventSink(cmd, nil, true), // several tunnels: the text form says which is which
		MaxInitialAttempts: max(cf.maxAttempts, 0),
		AcceptRemoteOpen:   true,
		RemoteOpen:         file.RemotePolicy(),
	})
	if err != nil {
		return explain(err)
	}
	return nil
}
