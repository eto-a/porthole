// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/proto"
)

// connFlags are the per-command overrides of the stored credentials.
type connFlags struct {
	server string
	token  string
}

func (f *connFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.server, "server", "", "server URL (overrides $"+envServer+" and the config file)")
	cmd.Flags().StringVar(&f.token, "token", "", "token (overrides $"+envToken+" and the config file)")
}

// credentials resolves server and token: flag, then environment, then config file.
func (a *app) credentials(f *connFlags) (server, token string, err error) {
	server, token = f.server, f.token
	if server == "" {
		server = a.d.getenv(envServer)
	}
	if token == "" {
		token = a.d.getenv(envToken)
	}
	if server == "" || token == "" {
		path, err := a.path()
		if err != nil {
			return "", "", err
		}
		cfg, err := loadConfig(path)
		if err != nil {
			return "", "", err
		}
		if server == "" {
			server = cfg.Server
		}
		if token == "" {
			token = cfg.Token
		}
	}
	if server == "" || token == "" {
		return "", "", fmt.Errorf("no server or token configured: run `porthole login <server-url> <token>`, "+
			"or set %s and %s", envServer, envToken)
	}
	if _, err := client.ConnectURL(server); err != nil {
		return "", "", err
	}
	if _, err := auth.Parse(token); err != nil {
		return "", "", errors.New("the configured token is malformed (expected ph_<id>_<secret>); run `porthole login` with a valid token")
	}
	return server, token, nil
}

func (a *app) newHTTPCmd() *cobra.Command {
	var cf connFlags
	var name string
	cmd := &cobra.Command{
		Use:   "http <port|host:port>",
		Short: "Expose a local HTTP service",
		Long:  "Expose a local HTTP service. A bare port means 127.0.0.1:<port>.",
		Example: "  porthole http 8080\n" +
			"  porthole http 192.168.1.10:3000 --name blog",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := parseTarget(args[0])
			if err != nil {
				return err
			}
			spec := client.TunnelSpec{Kind: proto.KindHTTP, Name: name, LocalAddr: target}
			return a.runTunnel(cmd, &cf, spec, "")
		},
	}
	cf.add(cmd)
	cmd.Flags().StringVar(&name, "name", "", "tunnel name (default http-<port>)")
	return cmd
}

func (a *app) newTCPCmd() *cobra.Command {
	var cf connFlags
	var name string
	var remotePort int
	cmd := &cobra.Command{
		Use:   "tcp <port|host:port>",
		Short: "Expose a local TCP service",
		Long:  "Expose a local TCP service on a public port of the server. A bare port means 127.0.0.1:<port>.",
		Example: "  porthole tcp 5432\n" +
			"  porthole tcp 5432 --remote-port 20017",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := parseTarget(args[0])
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("remote-port") {
				if _, err := parsePort(fmt.Sprint(remotePort)); err != nil {
					return fmt.Errorf("--remote-port: %w", err)
				}
			}
			spec := client.TunnelSpec{Kind: proto.KindTCP, Name: name, LocalAddr: target, RemotePort: remotePort}
			return a.runTunnel(cmd, &cf, spec, "")
		},
	}
	cf.add(cmd)
	cmd.Flags().StringVar(&name, "name", "", "tunnel name (default tcp-<port>)")
	cmd.Flags().IntVar(&remotePort, "remote-port", 0, "request this public port (default: any free port in the server's range)")
	return cmd
}

func (a *app) newSSHCmd() *cobra.Command {
	var cf connFlags
	var name, userName string
	var localPort int
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Expose the local ssh server",
		Long:  "Expose the local ssh server (a TCP tunnel to 127.0.0.1:22) and print the ssh command to reach it.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := parsePort(fmt.Sprint(localPort)); err != nil {
				return fmt.Errorf("--local-port: %w", err)
			}
			target, err := parseTarget(fmt.Sprint(localPort))
			if err != nil {
				return err
			}
			if userName == "" {
				userName = a.d.currentUser()
			}
			spec := client.TunnelSpec{Kind: proto.KindTCP, Name: name, LocalAddr: target}
			return a.runTunnel(cmd, &cf, spec, userName)
		},
	}
	cf.add(cmd)
	cmd.Flags().IntVar(&localPort, "local-port", 22, "local ssh port")
	cmd.Flags().StringVar(&userName, "user", "", "user name for the printed ssh command (default: current user)")
	cmd.Flags().StringVar(&name, "name", "ssh", "tunnel name")
	return cmd
}

// runTunnel runs one tunnel in the foreground until interrupted. sshUser is non-empty for `porthole ssh`.
func (a *app) runTunnel(cmd *cobra.Command, cf *connFlags, spec client.TunnelSpec, sshUser string) error {
	server, token, err := a.credentials(cf)
	if err != nil {
		return err
	}
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
	err = a.d.run(ctx, client.Options{
		ServerURL: server,
		Token:     token,
		Tunnels:   []client.TunnelSpec{spec},
		Version:   a.version,
		Logger:    a.logger(cmd),
		OnEvent:   func(e client.Event) { printEvent(out, errOut, e, sshUser) },
	})
	if err != nil {
		return explain(err)
	}
	return nil
}

// printEvent renders a client event for the terminal. Status goes to out, trouble to errOut.
func printEvent(out, errOut io.Writer, e client.Event, sshUser string) {
	switch e := e.(type) {
	case client.Connected:
		fmt.Fprintf(out, "connected as %s\n", e.ClientName)
	case client.TunnelReady:
		fmt.Fprintf(out, "%s -> %s\n", e.PublicURL, e.Spec.LocalAddr)
		if sshUser != "" {
			if cmdline, ok := sshCommand(e.PublicURL, sshUser); ok {
				fmt.Fprintf(out, "  %s\n", cmdline)
			}
		}
	case client.TunnelClosed:
		fmt.Fprintf(errOut, "tunnel %s closed: %s\n", e.Name, e.Reason)
	case client.Disconnected:
		secs := max(1, int(math.Ceil(e.RetryIn.Seconds())))
		fmt.Fprintf(errOut, "reconnecting in %ds: %v\n", secs, e.Err)
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
