// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/clientconfig"
	"github.com/eto-a/porthole/internal/daemon"
	"github.com/eto-a/porthole/internal/localapi"
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
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the client daemon: keep the tunnels of the tunnels file up",
		Long: "Run the porthole client daemon. It holds one session to the server, keeps the tunnels defined in the tunnels " +
			"file registered (reconnecting forever), and serves a local API on a unix socket that `porthole status`, " +
			"`reload`, `close` and the tunnel commands use. `porthole reload` and SIGHUP re-read the tunnels file.\n\n" +
			"The server and token come from the config file (see `porthole login`), $" + envServer + " and $" + envToken + ". " +
			"A broken configuration makes the daemon exit with status " + fmt.Sprint(ExitConfig) + ".",
		Example: "  porthole daemon\n" +
			"  porthole daemon --config /etc/porthole/config.yaml --tunnels /etc/porthole/tunnels.yaml \\\n" +
			"      --socket /run/porthole/porthole.sock",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.runDaemonCmd(cmd, tunnelsFlag) },
	}
	cmd.Flags().StringVar(&tunnelsFlag, "tunnels", "", "tunnels file (default: tunnels.yaml next to the config file)")
	return cmd
}

func (a *app) runDaemonCmd(cmd *cobra.Command, tunnelsFlag string) error {
	cfgErr := func(err error) error { return &ExitError{Code: ExitConfig, Err: err} }

	tunnels, err := a.tunnelsPath(tunnelsFlag)
	if err != nil {
		return cfgErr(err)
	}
	socket, err := a.daemonSocket()
	if err != nil {
		return cfgErr(err)
	}
	creds, err := a.resolveCreds(&connFlags{})
	if err != nil {
		return cfgErr(err)
	}
	if creds.token == "" {
		return cfgErr(fmt.Errorf("no token configured: run `porthole login <server-url> <token>`, or set %s", envToken))
	}
	mode := userSocketMode
	if socket == localapi.SystemSocketPath {
		mode = systemSocketMode
	}

	ctx, stop := signalContext(cmd)
	defer stop()
	err = a.d.runDaemon(ctx, daemon.Options{
		ServerURL:    creds.server,
		ConfigServer: creds.configServer,
		Token:        creds.token,
		TunnelsPath:  tunnels,
		SocketPath:   socket,
		SocketMode:   mode,
		Version:      a.version,
		Logger:       a.daemonLogger(cmd),
	})
	if err == nil {
		return nil
	}
	err = explain(err)
	var ce *daemon.ConfigError
	if errors.As(err, &ce) {
		return cfgErr(err)
	}
	return err
}

// daemonLogger logs at info level (a service wants its lifecycle in the journal); --verbose adds debug.
func (a *app) daemonLogger(cmd *cobra.Command) *slog.Logger {
	level := slog.LevelInfo
	if a.verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: level}))
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
		return fmt.Errorf("tunnels file %s does not exist; create it or pass --tunnels", path)
	}
	if err != nil {
		return err
	}
	specs, err := file.Specs(names...)
	if err != nil {
		return err
	}
	if len(specs) == 0 {
		return fmt.Errorf("%s defines no enabled tunnels; add some, or name the tunnels to start", path)
	}
	creds, err := a.resolveCreds(cf)
	if err != nil {
		return err
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
	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
	// A daemon that uses the same token would be replaced by this session and then evict it again.
	if _, socket, err := a.findDaemon(ctx); err == nil {
		fmt.Fprintf(errOut, "note: a porthole daemon is running (%s); if it uses the same token, this session replaces "+
			"its connection to the server. Use `porthole reload` to change the daemon's tunnels instead.\n", socket)
	}

	err = a.d.run(ctx, client.Options{
		ServerURL: server,
		Token:     token,
		Tunnels:   specs,
		Version:   a.version,
		Logger:    a.logger(cmd),
		OnEvent: func(e client.Event) {
			if r, ok := e.(client.TunnelReady); ok { // several tunnels: say which is which
				fmt.Fprintf(out, "%s: %s -> %s\n", r.Name, r.PublicURL, r.Spec.LocalAddr)
				return
			}
			printEvent(out, errOut, e, "")
		},
		MaxInitialAttempts: max(cf.maxAttempts, 0),
	})
	if err != nil {
		return explain(err)
	}
	return nil
}
