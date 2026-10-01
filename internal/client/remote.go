// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eto-a/porthole/internal/proto"
)

// DefaultSSHAddr is the local target of an ssh tunnel without an address, and the meaning of "ssh" in a remote
// policy.
const DefaultSSHAddr = "127.0.0.1:22"

// remotePollInterval is how often handleOpen looks at the tunnel it is waiting for.
const remotePollInterval = 25 * time.Millisecond

// RemotePolicy decides which local targets the server may ask this client to expose (Options.RemoteOpen). The
// policy is enforced by the client alone: the server cannot widen it.
//
// A nil *RemotePolicy is the default: only targets on this machine (a loopback address or "localhost", which includes
// the default ssh target 127.0.0.1:22). The zero value permits nothing. A policy with Targets permits exactly those
// "host:port" entries, and one with Any permits every target.
//
// Link-local targets (169.254.0.0/16, fe80::/10: cloud metadata services and the like) are refused unless they are
// listed in Targets verbatim, even under Any.
type RemotePolicy struct {
	// Targets are the permitted local targets, normalized with ParseTarget ("host:port"). Matching is exact.
	Targets []string
	// Any permits every target except the link-local ones (see above).
	Any bool
}

// Permits reports whether a request for the (normalized) local target addr is allowed.
func (p *RemotePolicy) Permits(addr string) bool {
	if p != nil && slices.Contains(p.Targets, addr) {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if isLinkLocalHost(host) {
		return false
	}
	if p == nil {
		return isLoopbackHost(host)
	}
	return p.Any
}

// isLoopbackHost reports whether host names this machine: "localhost" (any case, optional trailing dot) or a loopback
// IP literal. Other names are not trusted to resolve to a loopback address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// isLinkLocalHost reports whether host is a link-local IP literal (IPv4-mapped forms and zones included).
func isLinkLocalHost(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLinkLocalUnicast()
}

// ParseTarget turns a local target into "host:port". A bare port means 127.0.0.1:<port>, and so does ":port".
// The grammar is the one of the `porthole http|tcp|ssh` argument.
func ParseTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("missing local port or address")
	}
	if !strings.Contains(s, ":") {
		port, err := parsePort(s)
		if err != nil {
			return "", fmt.Errorf("invalid local target %q: want a port or host:port", s)
		}
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("invalid local target %q: want a port or host:port", s)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid local target %q: %w", s, err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if strings.ContainsAny(host, " \t/\\") {
		return "", fmt.Errorf("invalid local target %q: bad host", s)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %q must be a number from 1 to 65535", s)
	}
	return p, nil
}

// remoteTarget resolves the local_addr of an open request: empty or "ssh" for an ssh tunnel is DefaultSSHAddr.
func remoteTarget(kind, local string) (string, error) {
	local = strings.TrimSpace(local)
	if kind == proto.KindSSH && (local == "" || local == "ssh") {
		return DefaultSSHAddr, nil
	}
	return ParseTarget(local)
}

// openFailure builds a failed OpenResult.
func openFailure(reqID int, code, format string, a ...any) *proto.OpenResult {
	return &proto.OpenResult{ReqID: reqID, Error: &proto.OpenError{Code: code, Message: fmt.Sprintf(format, a...)}}
}

// handleOpen serves one open_request: it checks the policy, adds a runtime tunnel (like Manager.Add) and waits until
// the server registered it or refused it. It runs in its own goroutine and sends exactly one open_result unless the
// session ends first.
func (m *Manager) handleOpen(ctx context.Context, ctl *ctlConn, req *proto.OpenRequest) {
	res := m.openTunnel(ctx, req)
	if ctx.Err() != nil {
		return
	}
	if err := ctl.send(res); err != nil {
		m.log.Warn("send open_result", "err", err)
	}
}

func (m *Manager) openTunnel(ctx context.Context, req *proto.OpenRequest) *proto.OpenResult {
	m.log.Info("remote open requested", "kind", req.Kind, "local", req.LocalAddr, "name", req.Name, "by", req.RequestedBy)
	if !m.opts.AcceptRemoteOpen {
		return openFailure(req.ReqID, proto.CodeClientUnsupported, "this client does not accept remote tunnel requests")
	}
	if req.Kind != proto.KindHTTP && req.Kind != proto.KindTCP && req.Kind != proto.KindSSH {
		return openFailure(req.ReqID, proto.CodeInvalidRequest, "tunnel kind %q is not supported", req.Kind)
	}
	addr, err := remoteTarget(req.Kind, req.LocalAddr)
	if err != nil {
		return openFailure(req.ReqID, proto.CodeInvalidRequest, "%v", err)
	}
	if !m.RemoteOpen().Permits(addr) {
		m.log.Warn("remote open refused by allow_remote", "local", addr, "by", req.RequestedBy)
		return openFailure(req.ReqID, proto.CodeNotAllowed, "this machine does not allow remote requests for %s (see allow_remote in tunnels.yaml)", addr)
	}
	spec, err := m.Add(TunnelSpec{Kind: req.Kind, Name: req.Name, LocalAddr: addr, RemotePort: req.RemotePort, Private: req.Private})
	switch {
	case errors.Is(err, ErrTunnelExists):
		return openFailure(req.ReqID, proto.CodeNameTaken, "%v", err)
	case err != nil:
		return openFailure(req.ReqID, proto.CodeInvalidRequest, "%v", err)
	}

	timer := time.NewTimer(m.t.registerTimeout)
	defer timer.Stop()
	tick := time.NewTicker(remotePollInterval)
	defer tick.Stop()
	for {
		tunnels := m.Snapshot().Tunnels
		for i := range tunnels {
			ts := &tunnels[i]
			if ts.Spec.Name != spec.Name {
				continue
			}
			switch ts.Status {
			case StatusReady:
				return &proto.OpenResult{ReqID: req.ReqID, OK: true, Tunnel: &proto.OpenedTunnel{
					Name: spec.Name, Kind: spec.Kind, PublicURL: ts.PublicURL, SSHJump: ts.SSHJump,
				}}
			case StatusFailed:
				_ = m.Remove(spec.Name)
				code := proto.CodeInternal
				var pe *proto.Error
				if errors.As(ts.Err, &pe) {
					code = pe.Code
				}
				return openFailure(req.ReqID, code, "%v", ts.Err)
			case StatusPending:
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			_ = m.Remove(spec.Name)
			return openFailure(req.ReqID, proto.CodeTimeout, "the server did not confirm the tunnel in time")
		case <-tick.C:
		}
	}
}

// RemoteOpen returns the current policy for server-initiated tunnel requests (nil: this machine only).
func (m *Manager) RemoteOpen() *RemotePolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opts.RemoteOpen
}

// SetRemoteOpen replaces the policy for server-initiated tunnel requests, for example after the tunnels file was
// reloaded. Tunnels that are already open stay open. It has no effect on whether the client announces the feature,
// which is fixed by Options.AcceptRemoteOpen.
func (m *Manager) SetRemoteOpen(p *RemotePolicy) {
	m.mu.Lock()
	m.opts.RemoteOpen = p
	m.mu.Unlock()
}

// features lists the optional capabilities announced in hello.
func (m *Manager) features() []string {
	if m.opts.AcceptRemoteOpen {
		return []string{proto.FeatureRemoteOpen}
	}
	return nil
}
