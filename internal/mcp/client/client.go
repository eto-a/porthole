// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package client is the MCP server of an agent on a client machine (ADR 0005, surface B): `porthole mcp` serves
// tools that open and close tunnels through the local daemon. Access to the daemon's unix socket is the permission
// (ADR 0002); the agent never holds a token.
package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/eto-a/porthole/internal/localapi"
)

const (
	callTimeout         = 30 * time.Second
	defaultReadyTimeout = 15 * time.Second
	readyPollInterval   = 200 * time.Millisecond
)

// Daemon is the part of the local daemon API the tools use; *localapi.Client satisfies it.
type Daemon interface {
	Status(ctx context.Context) (localapi.Status, error)
	Tunnels(ctx context.Context) ([]localapi.Tunnel, error)
	AddTunnel(ctx context.Context, req localapi.AddTunnelRequest) (localapi.Tunnel, error)
	RemoveTunnel(ctx context.Context, name string) error
}

// Dial finds the daemon and returns it with a function that releases it. It is called for every tool call, so the
// agent may start before the daemon does.
type Dial func(ctx context.Context) (Daemon, func(), error)

// Options configures New.
type Options struct {
	Dial Dial
	// ReadOnly registers no tool that changes anything.
	ReadOnly bool
	// ReadyTimeout bounds how long open_tunnel waits for the tunnel to come up. Default 15 s.
	ReadyTimeout time.Duration
	Logger       *slog.Logger
	Version      string
}

type server struct {
	opts Options
}

// New builds the MCP server over the daemon that opts.Dial finds.
func New(opts Options) (*mcp.Server, error) {
	if opts.Dial == nil {
		return nil, errors.New("mcp client: Dial is required")
	}
	if opts.ReadyTimeout <= 0 {
		opts.ReadyTimeout = defaultReadyTimeout
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	s := &server{opts: opts}
	srv := mcp.NewServer(&mcp.Implementation{Name: "porthole", Version: opts.Version}, &mcp.ServerOptions{
		Instructions: "Tools to expose services of this machine through the porthole tunnel server and to see what is exposed.",
		Logger:       opts.Logger,
	})
	t, f := true, false

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "status",
		Description: "State of the porthole daemon on this machine: server, connection state, last error and tunnels.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, localapi.Status, error) {
		var st localapi.Status
		err := s.with(ctx, func(ctx context.Context, d Daemon) (err error) { st, err = d.Status(ctx); return })
		return nil, st, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_tunnels",
		Description: "List the tunnels of this machine's daemon: name, type, local address, public URL or port, state.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, tunnelsOut, error) {
		var ts []localapi.Tunnel
		err := s.with(ctx, func(ctx context.Context, d Daemon) (err error) { ts, err = d.Tunnels(ctx); return })
		if ts == nil {
			ts = []localapi.Tunnel{}
		}
		return nil, tunnelsOut{Tunnels: ts}, err
	})

	if opts.ReadOnly {
		return srv, nil
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name: "open_tunnel",
		Description: "Expose a local service to the internet through the porthole server and return its public address. " +
			"The tunnel lasts until close_tunnel or a daemon restart. This makes the service reachable by anyone with the " +
			"address (ssh: only with a porthole token when private=true), so open only what the user asked for.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &f, IdempotentHint: false, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in openIn) (*mcp.CallToolResult, localapi.Tunnel, error) {
		if !slices.Contains([]string{localapi.TypeHTTP, localapi.TypeTCP, localapi.TypeSSH}, in.Type) {
			return nil, localapi.Tunnel{}, errors.New("type must be http, tcp or ssh")
		}
		var tun localapi.Tunnel
		err := s.with(ctx, func(ctx context.Context, d Daemon) error {
			var err error
			tun, err = s.open(ctx, d, localapi.AddTunnelRequest{
				Type: in.Type, Name: in.Name, Addr: in.LocalAddr, Lifetime: localapi.LifetimeRuntime, Private: in.Private,
			})
			return err
		})
		return nil, tun, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "close_tunnel",
		Description: "Close a tunnel of this machine by name (from list_tunnels). Its public address stops working.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &t, IdempotentHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in closeIn) (*mcp.CallToolResult, closeOut, error) {
		if in.Name == "" {
			return nil, closeOut{}, errors.New("name is required")
		}
		err := s.with(ctx, func(ctx context.Context, d Daemon) error { return d.RemoveTunnel(ctx, in.Name) })
		return nil, closeOut{OK: err == nil}, err
	})
	return srv, nil
}

type tunnelsOut struct {
	Tunnels []localapi.Tunnel `json:"tunnels"`
}

type openIn struct {
	Type      string `json:"type" jsonschema:"http, tcp or ssh"`
	LocalAddr string `json:"local_addr" jsonschema:"what to expose: a port such as 3000, or host:port"`
	Name      string `json:"name,omitempty" jsonschema:"tunnel name; for http it becomes the subdomain; default: chosen by the server"`
	Private   bool   `json:"private,omitempty" jsonschema:"ssh only: the gateway requires a porthole token"`
}

type closeIn struct {
	Name string `json:"name" jsonschema:"tunnel name from list_tunnels"`
}

type closeOut struct {
	OK bool `json:"ok"`
}

// with dials the daemon for one call and turns its errors into text for the model.
func (s *server) with(ctx context.Context, fn func(context.Context, Daemon) error) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	d, release, err := s.opts.Dial(ctx)
	if err != nil {
		return err
	}
	if release != nil {
		defer release()
	}
	err = fn(ctx, d)
	var le *localapi.Error
	if errors.As(err, &le) {
		return fmt.Errorf("the porthole daemon refused: %s: %s", le.Code, le.Message)
	}
	return err
}

// open adds the tunnel and waits until it is ready, failed or the timeout passes (then the pending tunnel is
// returned: it may still come up).
func (s *server) open(ctx context.Context, d Daemon, req localapi.AddTunnelRequest) (localapi.Tunnel, error) {
	tun, err := d.AddTunnel(ctx, req)
	if err != nil {
		return localapi.Tunnel{}, err
	}
	deadline := time.NewTimer(s.opts.ReadyTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(readyPollInterval)
	defer tick.Stop()
	for {
		switch tun.State {
		case localapi.TunnelReady:
			return tun, nil
		case localapi.TunnelFailed:
			return tun, fmt.Errorf("the tunnel %q failed: %s", tun.Name, tun.Error)
		}
		select {
		case <-ctx.Done():
			return tun, ctx.Err()
		case <-deadline.C:
			return tun, nil
		case <-tick.C:
		}
		ts, err := d.Tunnels(ctx)
		if err != nil {
			return tun, err
		}
		for i := range ts {
			if ts[i].Name == tun.Name {
				tun = ts[i]
			}
		}
	}
}
