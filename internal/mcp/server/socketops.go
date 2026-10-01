// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
)

// SocketOps implements Ops over the admin unix socket, for `portholed mcp`. Whoever may open the socket is a full
// administrator; the admin API audits mutating calls itself (actor "socket"). The traffic tools go through the admin
// API endpoints, which serve the in-memory logs of the server process.
type SocketOps struct {
	Client *adminapi.SocketClient
}

var _ Ops = SocketOps{}

func (o SocketOps) Status(ctx context.Context) (adminapi.Status, error) { return o.Client.Status(ctx) }

func (o SocketOps) Clients(ctx context.Context) ([]adminapi.Client, error) {
	return o.Client.Clients(ctx)
}

func (o SocketOps) DisconnectClient(ctx context.Context, name string) error {
	return o.Client.Disconnect(ctx, name)
}

func (o SocketOps) Tunnels(ctx context.Context) ([]adminapi.Tunnel, error) {
	return o.Client.Tunnels(ctx)
}

func (o SocketOps) CloseTunnel(ctx context.Context, id string) error {
	return o.Client.CloseTunnel(ctx, id)
}

// RequestTunnel calls POST clients/{name}/tunnels. Refusals arrive as *adminapi.Error with the codes of
// adminapi.RemoteError; an offline client is adminapi.ErrNotFound.
func (o SocketOps) RequestTunnel(ctx context.Context, p RequestTunnelParams) (RequestTunnelResult, error) {
	t, err := o.Client.RequestTunnel(ctx, p.Client, adminapi.RemoteOpen{
		Kind: p.Kind, LocalAddr: p.LocalAddr, Name: p.Name, Private: p.Private, // RequestedBy is set by the API: "socket"
	})
	if err != nil {
		var api *adminapi.Error
		if errors.As(err, &api) && api.Code == "not_found" {
			return RequestTunnelResult{}, adminapi.ErrNotFound
		}
		return RequestTunnelResult{}, err
	}
	return RequestTunnelResult{Tunnel: t}, nil
}

func (o SocketOps) Tokens(ctx context.Context) ([]adminapi.Token, error) {
	return o.Client.Tokens(ctx)
}

func (o SocketOps) RevokeToken(ctx context.Context, id string) error {
	return o.Client.RevokeToken(ctx, id)
}

// CreateJoinLink calls POST join; the server builds the link and audits the call (actor "socket").
func (o SocketOps) CreateJoinLink(ctx context.Context, p JoinLinkParams) (JoinLink, error) {
	req := adminapi.JoinRequest{ClientName: p.Client, Scopes: p.Scopes, RemoteControl: &p.AllowRemote}
	if p.TTL > 0 {
		req.TTL = p.TTL.String()
	}
	jc, err := o.Client.CreateJoin(ctx, req)
	if err != nil {
		return JoinLink{}, err
	}
	return JoinLink{URL: jc.Link, Command: jc.Command, Client: jc.ClientName, ExpiresAt: jc.ExpiresAt}, nil
}

func (o SocketOps) QueryRequests(ctx context.Context, q RequestQuery) (RequestsResult, error) {
	f := requestFilter(q)
	reqs, err := o.Client.Requests(ctx, f)
	if err != nil {
		return RequestsResult{}, err
	}
	res := RequestsResult{Requests: make([]Request, 0, len(reqs))}
	for i := range reqs {
		res.Requests = append(res.Requests, requestDTO(&reqs[i]))
	}
	if q.Aggregate {
		ag, err := o.Client.RequestAggregates(ctx, f, q.TopN)
		if err != nil {
			return RequestsResult{}, err
		}
		a := aggregatesDTO(ag)
		res.Aggregates = &a
	}
	return res, nil
}

func (o SocketOps) GetRequest(ctx context.Context, id uint64) (Request, error) {
	r, err := o.Client.Request(ctx, id)
	if err != nil {
		return Request{}, err
	}
	return requestDTO(&r), nil
}

func (o SocketOps) ReplayRequest(ctx context.Context, id uint64) (Request, error) {
	r, err := o.Client.ReplayRequest(ctx, id)
	if err != nil {
		return Request{}, err
	}
	return requestDTO(&r), nil
}

func (o SocketOps) ConnectionLog(ctx context.Context, q ConnQuery) ([]Conn, error) {
	cs, err := o.Client.Connections(ctx, connFilter(q))
	if err != nil {
		return nil, err
	}
	return connsDTO(cs), nil
}

func (o SocketOps) GatewayAuthFailures(ctx context.Context, since time.Time, limit int) ([]Conn, error) {
	cs, err := o.Client.AuthFailures(ctx, since, limit)
	if err != nil {
		return nil, err
	}
	return connsDTO(cs), nil
}

func (o SocketOps) AuditLog(ctx context.Context, limit int) ([]adminapi.AuditEntry, error) {
	return o.Client.Audit(ctx, limit)
}
