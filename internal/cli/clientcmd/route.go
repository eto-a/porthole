// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

const (
	// probeTimeout bounds the status request that tells whether a socket belongs to a live daemon.
	probeTimeout = 3 * time.Second
	// callTimeout bounds the one-shot requests of status, reload, close and so on.
	callTimeout = 30 * time.Second
	// defaultDetachTimeout is how long `--detach` waits for the tunnel to become ready.
	defaultDetachTimeout = 30 * time.Second
	detachPollInterval   = 100 * time.Millisecond
)

// noDaemonError means that no daemon answers on any socket that was looked at.
type noDaemonError struct{ tried []string }

func (e *noDaemonError) Error() string {
	if len(e.tried) == 0 {
		return "no porthole daemon socket to look at: pass --socket or set $" + envSocket
	}
	return "no porthole daemon is running (looked at " + strings.Join(e.tried, ", ") + "); " +
		"start one with `porthole daemon` or the system service"
}

func isNoDaemon(err error) bool {
	var e *noDaemonError
	return errors.As(err, &e)
}

// deniedError means that a daemon socket exists but this user may not use it.
type deniedError struct {
	path string
	err  error
}

func (e *deniedError) Error() string {
	return fmt.Sprintf("permission denied on the porthole daemon socket %s: add your user to the group that owns it "+
		"(for the system daemon: `sudo usermod -aG porthole-client $USER`, then log in again), or use --no-daemon "+
		"to run in this process with your own token", e.path)
}

func (e *deniedError) Unwrap() error { return e.err }

// socketCandidates lists the sockets to look at, in the order of ADR 0002: --socket, $PORTHOLE_SOCKET, then the
// default locations. An explicit --socket is the only candidate.
func (a *app) socketCandidates() []string {
	if a.socket != "" {
		return []string{a.socket}
	}
	var paths []string
	add := func(p string) {
		if p != "" && !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	add(a.d.getenv(envSocket))
	if a.d.socketPaths != nil {
		for _, p := range a.d.socketPaths() {
			add(p)
		}
	}
	return paths
}

// findDaemon looks for a live daemon. It returns the client of the first socket that answers. Otherwise the error is
// a *noDaemonError (nothing listens anywhere), a *deniedError (a socket exists but is not ours; a daemon that answers
// on a later candidate still wins), or another error when something answers on a socket but misbehaves.
func (a *app) findDaemon(ctx context.Context) (apiClient, string, error) {
	paths := a.socketCandidates()
	var denied *deniedError
	for _, p := range paths {
		cl := a.d.dial(p)
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		_, err := cl.Status(pctx)
		cancel()
		switch {
		case err == nil:
			return cl, p, nil
		case localapi.IsUnavailable(err):
			cl.Close()
		case localapi.IsPermissionDenied(err):
			cl.Close()
			if denied == nil {
				denied = &deniedError{path: p, err: err}
			}
		default:
			cl.Close()
			return nil, "", fmt.Errorf("the porthole daemon at %s does not answer properly: %w", p, err)
		}
	}
	if denied != nil {
		return nil, "", denied
	}
	return nil, "", &noDaemonError{tried: paths}
}

// requireDaemon is findDaemon for the commands that only make sense with a daemon.
func (a *app) requireDaemon(ctx context.Context) (apiClient, string, error) {
	cl, path, err := a.findDaemon(ctx)
	if err != nil {
		var de *deniedError
		if errors.As(err, &de) {
			return nil, "", &explainedError{
				msg: fmt.Sprintf("permission denied on the porthole daemon socket %s: add your user to the group that owns it "+
					"(for the system daemon: `sudo usermod -aG porthole-client $USER`, then log in again)", de.path),
				err: err,
			}
		}
		return nil, "", err
	}
	return cl, path, nil
}

// apiErr turns an error of a local API call into a message for the user.
func apiErr(err error, socket string) error {
	var e *localapi.Error
	switch {
	case err == nil:
		return nil
	case localapi.IsUnavailable(err):
		return &explainedError{msg: fmt.Sprintf("the porthole daemon at %s is not answering any more", socket), err: err}
	case localapi.IsPermissionDenied(err):
		return &explainedError{msg: (&deniedError{path: socket}).Error(), err: err}
	case errors.As(err, &e):
		return &explainedError{msg: e.Message, err: err}
	default:
		return err
	}
}

// addErr is apiErr for the commands that add a tunnel.
func addErr(err error, socket string) error {
	var e *localapi.Error
	if errors.As(err, &e) && e.Code == localapi.CodeNameTaken {
		return &explainedError{msg: e.Message + "; choose another one with --name", err: err}
	}
	return apiErr(err, socket)
}

// reasonError rebuilds the server's error from the reason of a tunnel_closed event ("code: message").
func reasonError(reason string) error {
	code, msg, found := strings.Cut(reason, ": ")
	if !found {
		code, msg = reason, ""
	}
	if code == "" || strings.ContainsAny(code, " \t") {
		return errors.New(reason)
	}
	return &proto.Error{Code: code, Message: msg}
}

// toClientEvent converts a daemon event so that printEvent can render it exactly like an in-process one. tun is the
// tunnel the stream belongs to.
func toClientEvent(ev localapi.Event, tun localapi.Tunnel) (client.Event, bool) {
	switch ev.Type {
	case localapi.EventConnected:
		return client.Connected{ClientName: ev.ClientName}, true
	case localapi.EventDisconnected:
		msg := ev.Error
		if msg == "" {
			msg = "connection lost"
		}
		return client.Disconnected{Err: errors.New(msg), RetryIn: time.Duration(ev.RetryInMS) * time.Millisecond}, true
	case localapi.EventTunnelReady:
		return client.TunnelReady{
			Spec:      client.TunnelSpec{Kind: tun.Type, Name: tun.Name, LocalAddr: tun.LocalAddr, Private: tun.Private, Inspect: tun.Inspect},
			Name:      ev.Name,
			PublicURL: ev.PublicURL,
			SSHJump:   ev.SSHJump,
		}, true
	case localapi.EventTunnelClosed:
		return client.TunnelClosed{Name: ev.Name, Reason: ev.Reason}, true
	default:
		return nil, false
	}
}

// attachTunnel adds the tunnel to the daemon as an attached tunnel and keeps it for as long as this command runs.
func (a *app) attachTunnel(ctx context.Context, cmd *cobra.Command, cl apiClient, socket string, tr tunnelRequest) error {
	errOut := cmd.ErrOrStderr()
	var tun localapi.Tunnel
	ready, removed := false, false
	var failure error
	hint := tr.hint()
	sink := eventSink(cmd, hint, false)
	asJSON := jsonout.Enabled(cmd)

	err := cl.Attach(ctx, tr.apiRequest(), func(ev localapi.Event) error {
		switch ev.Type {
		case localapi.EventAttached:
			if ev.Tunnel != nil {
				tun = *ev.Tunnel
			}
			return nil
		case localapi.EventTunnelClosed:
			if ev.Name != tun.Name {
				return nil
			}
			switch {
			case ev.Error == "": // removed on the daemon (`porthole close`, or a reload that replaced it)
				if asJSON {
					sink(client.TunnelClosed{Name: ev.Name, Reason: "removed on the daemon"})
				} else {
					fmt.Fprintf(errOut, "tunnel %s was removed on the daemon\n", ev.Name)
				}
				removed = true
				return localapi.ErrStopStream
			case !ready: // the server refused the registration: report and give up, like the in-process client
				failure = explain(reasonError(ev.Reason))
				// Free the name now: a fallback to another tunnel kind may reuse it at once.
				removeQuietly(ctx, cl, tun.Name)
				return localapi.ErrStopStream
			}
		case localapi.EventTunnelReady:
			if ev.Name == tun.Name {
				ready = true
				a.learnClient(ctx, cl, hint)
			}
		}
		if ce, ok := toClientEvent(ev, tun); ok {
			sink(ce)
		}
		return nil
	})
	switch {
	case failure != nil:
		return failure
	case removed:
		return nil // reported above
	case err != nil && ctx.Err() != nil:
		return nil //nolint:nilerr // Ctrl-C is how a foreground tunnel ends; the daemon removes it when the connection closes
	case err != nil:
		return addErr(err, socket)
	default:
		// The stream ended without us asking: the daemon is shutting down.
		return &explainedError{
			msg: fmt.Sprintf("the porthole daemon at %s closed the connection; the tunnel is gone", socket),
			err: errors.New("event stream ended"),
		}
	}
}

// detachTunnel adds a runtime tunnel to the daemon, waits until it is ready, prints its address and returns.
func (a *app) detachTunnel(ctx context.Context, cmd *cobra.Command, cl apiClient, socket string, tr tunnelRequest) error {
	out := cmd.OutOrStdout()
	tun, err := cl.AddTunnel(ctx, tr.apiRequest())
	if err != nil {
		return addErr(err, socket)
	}
	timeout := a.d.detachTimeout
	if timeout <= 0 {
		timeout = defaultDetachTimeout
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(detachPollInterval)
	defer tick.Stop()
	for {
		tunnels, err := cl.Tunnels(ctx)
		if err != nil {
			return apiErr(err, socket)
		}
		if t, ok := findTunnel(tunnels, tun.Name); ok {
			switch t.State {
			case localapi.TunnelReady:
				if jsonout.Enabled(cmd) {
					return jsonout.Write(out, t)
				}
				hint := tr.hint()
				a.learnClient(ctx, cl, hint)
				printEvent(out, cmd.ErrOrStderr(), client.TunnelReady{
					Spec: client.TunnelSpec{Kind: t.Type, Name: t.Name, LocalAddr: t.LocalAddr, Private: t.Private, Inspect: t.Inspect},
					Name: t.Name, PublicURL: t.PublicURL, SSHJump: t.SSHJump,
				}, hint)
				fmt.Fprintf(out, "  stays until `porthole close %s` or a daemon restart\n", t.Name)
				return nil
			case localapi.TunnelFailed:
				removeQuietly(ctx, cl, t.Name) // do not leave a tunnel behind that the user was told failed
				return explain(reasonError(t.Error))
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return fmt.Errorf("tunnel %s is not ready after %s (the daemon may not be connected to the server); "+
				"it stays added and keeps trying: see `porthole status`, remove it with `porthole close %s`",
				tun.Name, timeout, tun.Name)
		case <-tick.C:
		}
	}
}

// learnClient fills in the client name of hint from the daemon's status: an attach stream does not repeat the
// connected event when the daemon was connected long ago. A failure only leaves a placeholder in the hint.
func (a *app) learnClient(ctx context.Context, cl apiClient, hint *sshHint) {
	if hint == nil || hint.client != "" {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if st, err := cl.Status(sctx); err == nil {
		hint.client = st.ClientName
	}
}

func findTunnel(ts []localapi.Tunnel, name string) (localapi.Tunnel, bool) {
	for i := range ts {
		if ts[i].Name == name {
			return ts[i], true
		}
	}
	return localapi.Tunnel{}, false
}

// removeQuietly removes a tunnel on a best-effort basis, even if ctx is already cancelled.
func removeQuietly(ctx context.Context, cl apiClient, name string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), callTimeout)
	defer cancel()
	_ = cl.RemoveTunnel(rctx, name)
}
