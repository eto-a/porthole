// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/clientconfig"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

// defaultFileName is how the tunnels file is called in messages when the path is unknown.
const defaultFileName = "tunnels.yaml"

func (d *Daemon) fileName() string {
	if d.opts.TunnelsPath == "" {
		return defaultFileName
	}
	return filepath.Base(d.opts.TunnelsPath)
}

// Status implements [localapi.Backend].
func (d *Daemon) Status(context.Context) localapi.Status {
	d.mu.Lock()
	st := d.mgr.Snapshot()
	tunnels := d.tunnelsLocked(st)
	d.mu.Unlock()

	out := localapi.Status{
		Version:     d.opts.Version,
		PID:         os.Getpid(),
		StartedAt:   d.startedAt,
		Server:      d.server,
		State:       connState(st.Conn),
		ClientName:  st.ClientName,
		TunnelsFile: d.opts.TunnelsPath,
		Tunnels:     tunnels,
	}
	if !st.RetryAt.IsZero() {
		at := st.RetryAt.UTC()
		out.RetryAt = &at
	}
	if st.LastErr != nil {
		out.LastError = errText(st.LastErr)
	}
	return out
}

// Tunnels implements [localapi.Backend]. The list is ordered by name.
func (d *Daemon) Tunnels(context.Context) []localapi.Tunnel {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tunnelsLocked(d.mgr.Snapshot())
}

// tunnelsLocked maps a manager snapshot to API tunnels. d.mu must be held.
func (d *Daemon) tunnelsLocked(st client.State) []localapi.Tunnel {
	out := make([]localapi.Tunnel, 0, len(st.Tunnels))
	for _, ts := range st.Tunnels {
		out = append(out, d.toTunnel(ts))
	}
	return out
}

func (d *Daemon) toTunnel(ts client.TunnelState) localapi.Tunnel {
	// A tunnel the daemon has no record of cannot exist (both are changed under d.mu); treat it as runtime to be safe.
	e, ok := d.meta[ts.Spec.Name]
	if !ok {
		e = entry{lifetime: localapi.LifetimeRuntime}
	}
	t := localapi.Tunnel{
		Name:       ts.Spec.Name,
		Type:       ts.Spec.Kind,
		LocalAddr:  ts.Spec.LocalAddr,
		RemotePort: ts.Spec.RemotePort,
		PublicURL:  ts.PublicURL,
		State:      tunnelState(ts.Status),
		Source:     e.source(),
		Lifetime:   e.lifetime,
	}
	if ts.Err != nil {
		t.Error = errText(ts.Err)
	}
	return t
}

func connState(c client.ConnState) string {
	switch c {
	case client.ConnConnected:
		return localapi.StateConnected
	case client.ConnBackoff:
		return localapi.StateBackoff
	case client.ConnStopped:
		return string(c)
	default: // idle and connecting
		return localapi.StateConnecting
	}
}

func tunnelState(s client.TunnelStatus) string {
	switch s {
	case client.StatusReady:
		return localapi.TunnelReady
	case client.StatusFailed:
		return localapi.TunnelFailed
	default:
		return localapi.TunnelPending
	}
}

// errText renders a manager error for the API: a refusal of the server becomes "code: message" without the
// "register tunnel" wrapping, which the tunnel name next to it already says.
func errText(err error) string {
	var perr *proto.Error
	if errors.As(err, &perr) {
		return perr.Error()
	}
	return err.Error()
}

// AddTunnel implements [localapi.Backend].
func (d *Daemon) AddTunnel(_ context.Context, req localapi.AddTunnelRequest) (localapi.Tunnel, error) {
	spec, err := specFromRequest(req)
	if err != nil {
		return localapi.Tunnel{}, err
	}
	lifetime := req.Lifetime
	if lifetime != localapi.LifetimeAttached && lifetime != localapi.LifetimeRuntime {
		return localapi.Tunnel{}, localapi.NewError(localapi.CodeInvalidRequest, "lifetime must be attached or runtime")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if e, taken := d.meta[spec.Name]; taken {
		if e.lifetime == localapi.LifetimeFile {
			return localapi.Tunnel{}, localapi.NewError(localapi.CodeNameTaken,
				"tunnel name %q is defined in %s; pick another name", spec.Name, d.fileName())
		}
		return localapi.Tunnel{}, localapi.NewError(localapi.CodeNameTaken, "tunnel name %q is already in use", spec.Name)
	}
	spec, err = d.mgr.Add(spec)
	if err != nil {
		return localapi.Tunnel{}, addError(err)
	}
	d.meta[spec.Name] = entry{lifetime: lifetime}
	d.log.Info("tunnel added", "tunnel", spec.Name, "kind", spec.Kind, "local", spec.LocalAddr, "lifetime", lifetime)
	return d.toTunnel(client.TunnelState{Spec: spec, Status: client.StatusPending}), nil
}

// addError maps a Manager.Add error to an API error.
func addError(err error) error {
	switch {
	case errors.Is(err, client.ErrTunnelExists):
		return localapi.NewError(localapi.CodeNameTaken, "%v", err)
	case errors.Is(err, client.ErrStopped):
		return localapi.NewError(proto.CodeShuttingDown, "the daemon is shutting down")
	default:
		return localapi.NewError(localapi.CodeInvalidRequest, "%v", err)
	}
}

// specFromRequest converts and validates an API request. ssh is a tcp tunnel to 127.0.0.1:22 named "ssh" by default.
func specFromRequest(req localapi.AddTunnelRequest) (client.TunnelSpec, error) {
	bad := func(format string, a ...any) error {
		return localapi.NewError(localapi.CodeInvalidRequest, format, a...)
	}
	var kind string
	switch req.Type {
	case localapi.TypeHTTP:
		kind = proto.KindHTTP
	case localapi.TypeTCP, localapi.TypeSSH:
		kind = proto.KindTCP
	default:
		return client.TunnelSpec{}, bad("type must be http, tcp or ssh")
	}
	addr := req.Addr
	if addr == "" && req.Type == localapi.TypeSSH {
		addr = clientconfig.DefaultSSHAddr
	}
	addr, err := clientconfig.ParseTarget(addr)
	if err != nil {
		return client.TunnelSpec{}, bad("addr: %v", err)
	}
	if req.RemotePort != 0 {
		if req.RemotePort < 1 || req.RemotePort > 65535 {
			return client.TunnelSpec{}, bad("remote_port %d out of range (1-65535)", req.RemotePort)
		}
		if kind != proto.KindTCP {
			return client.TunnelSpec{}, bad("remote_port is only valid for tcp and ssh tunnels")
		}
	}
	name := req.Name
	if name == "" {
		if req.Type == localapi.TypeSSH {
			name = localapi.TypeSSH
		} else {
			_, port, _ := net.SplitHostPort(addr) // ParseTarget returned a valid host:port
			name = kind + "-" + port
		}
	}
	return client.TunnelSpec{Kind: kind, Name: name, LocalAddr: addr, RemotePort: req.RemotePort}, nil
}

// RemoveTunnel implements [localapi.Backend]. Tunnels of the tunnels file cannot be removed this way.
func (d *Daemon) RemoveTunnel(_ context.Context, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.meta[name]
	if !ok {
		return localapi.NewError(localapi.CodeNotFound, "no tunnel named %q", name)
	}
	if e.lifetime == localapi.LifetimeFile {
		return localapi.NewError(localapi.CodeConflict,
			"tunnel %q is defined in %s; edit it and run `porthole reload`", name, d.fileName())
	}
	if err := d.mgr.Remove(name); err != nil {
		switch {
		case errors.Is(err, client.ErrTunnelNotFound):
			delete(d.meta, name)
			return localapi.NewError(localapi.CodeNotFound, "no tunnel named %q", name)
		case errors.Is(err, client.ErrStopped):
			return localapi.NewError(proto.CodeShuttingDown, "the daemon is shutting down")
		default:
			return fmt.Errorf("remove tunnel %q: %w", name, err)
		}
	}
	delete(d.meta, name)
	d.log.Info("tunnel removed", "tunnel", name, "lifetime", e.lifetime)
	return nil
}

// Reload implements [localapi.Backend]: it re-reads the tunnels file and makes the file-defined tunnels equal to it.
//
// The whole file is loaded and validated first; on any error the current set is kept and the error is returned as
// invalid_request. A file that existed at the last load but is gone now counts as an error too (an editor that
// replaces the file may leave a gap; deleting the file does not stop the tunnels, emptying it does).
//
// Runtime and attached tunnels are never removed by a reload. If the file defines a tunnel whose name is used by one
// of them, the file wins: the tunnel becomes a file tunnel (it is not re-registered when the specification is the
// same, and re-registered with the file's specification when it differs). A reload cannot change the server: that
// needs a restart, and a change is logged as a warning.
func (d *Daemon) Reload(context.Context) (localapi.ReloadResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.opts.TunnelsPath == "" {
		return localapi.ReloadResult{}, localapi.NewError(localapi.CodeInvalidRequest, "the daemon runs without a tunnels file")
	}
	file, existed, err := loadFile(d.opts.TunnelsPath)
	if err != nil {
		return localapi.ReloadResult{}, localapi.NewError(localapi.CodeInvalidRequest, "%v (keeping the current tunnels)", err)
	}
	if !existed && d.fileExists {
		return localapi.ReloadResult{}, localapi.NewError(localapi.CodeInvalidRequest,
			"tunnels file %s does not exist any more (keeping the current tunnels)", d.opts.TunnelsPath)
	}
	fileSpecs, err := file.Specs()
	if err != nil {
		return localapi.ReloadResult{}, localapi.NewError(localapi.CodeInvalidRequest,
			"tunnels file %s: %v (keeping the current tunnels)", d.opts.TunnelsPath, err)
	}
	if want := effectiveServer(d.opts, file); want != d.server {
		d.log.Warn("the server in the tunnels file changed; restart the daemon to use it", "running", d.server, "file", want)
	}

	inFile := make(map[string]bool, len(fileSpecs))
	for _, sp := range fileSpecs {
		inFile[sp.Name] = true
	}
	all := slices.Clone(fileSpecs)
	for _, ts := range d.mgr.Snapshot().Tunnels {
		name := ts.Spec.Name
		if d.meta[name].lifetime == localapi.LifetimeFile || inFile[name] {
			continue // old file tunnels follow the new file; a same-named tunnel is replaced by the file's
		}
		all = append(all, ts.Spec)
	}
	added, removed, changed, err := d.mgr.Replace(all)
	if err != nil {
		if errors.Is(err, client.ErrStopped) {
			return localapi.ReloadResult{}, localapi.NewError(proto.CodeShuttingDown, "the daemon is shutting down")
		}
		return localapi.ReloadResult{}, fmt.Errorf("apply tunnels file: %w", err)
	}

	for _, name := range removed {
		delete(d.meta, name)
	}
	for _, sp := range fileSpecs {
		d.meta[sp.Name] = entry{lifetime: localapi.LifetimeFile}
	}
	d.fileExists = existed

	res := localapi.ReloadResult{Added: added, Removed: removed, Changed: changed, Unchanged: []string{}}
	for _, sp := range fileSpecs {
		if !slices.Contains(added, sp.Name) && !slices.Contains(changed, sp.Name) {
			res.Unchanged = append(res.Unchanged, sp.Name)
		}
	}
	d.log.Info("tunnels file reloaded", "added", added, "removed", removed, "changed", changed, "unchanged", len(res.Unchanged))
	return res, nil
}

// Subscribe implements [localapi.Backend]. Manager events are translated; a consumer that does not keep up misses
// events (the manager never waits for it).
func (d *Daemon) Subscribe(ctx context.Context) <-chan localapi.Event {
	out := make(chan localapi.Event, subscriberBuffer)
	in, cancel := d.mgr.Subscribe(subscriberBuffer)
	go func() {
		defer close(out)
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-in:
				if !ok {
					return
				}
				ev, ok := toEvent(e)
				if !ok {
					continue
				}
				select {
				case out <- ev:
				default:
				}
			}
		}
	}()
	return out
}

// toEvent translates a manager event. The set changes (TunnelAdded) are not reported; a removal is reported as
// tunnel_closed without an Error, a failure as tunnel_closed with Error set.
func toEvent(e client.Event) (localapi.Event, bool) {
	now := time.Now().UTC()
	switch e := e.(type) {
	case client.Connected:
		return localapi.Event{Type: localapi.EventConnected, ClientName: e.ClientName, Time: now}, true
	case client.Disconnected:
		ev := localapi.Event{Type: localapi.EventDisconnected, RetryInMS: e.RetryIn.Milliseconds(), Time: now}
		if e.Err != nil {
			ev.Error = errText(e.Err)
		}
		return ev, true
	case client.TunnelReady:
		return localapi.Event{Type: localapi.EventTunnelReady, Name: e.Name, PublicURL: e.PublicURL, Time: now}, true
	case client.TunnelClosed:
		return localapi.Event{Type: localapi.EventTunnelClosed, Name: e.Name, Reason: e.Reason, Error: e.Reason, Time: now}, true
	case client.TunnelRemoved:
		return localapi.Event{Type: localapi.EventTunnelClosed, Name: e.Name, Reason: "removed", Time: now}, true
	default:
		return localapi.Event{}, false
	}
}
