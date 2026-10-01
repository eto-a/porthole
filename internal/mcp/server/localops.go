// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/traffic"
)

const storeTimeout = 5 * time.Second

// LocalOps implements Ops inside the server process, over the same Backend and Store as the admin API plus the
// traffic log.
type LocalOps struct {
	Backend adminapi.Backend
	Store   adminapi.Store
	// Traffic may be nil: the traffic tools then return empty results.
	Traffic *traffic.Log
	// ServerURL is the public URL join links are built on.
	ServerURL string
	Now       func() time.Time
}

var _ Ops = (*LocalOps)(nil)

func (o *LocalOps) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *LocalOps) Status(ctx context.Context) (adminapi.Status, error) { return o.Backend.Status(ctx) }

func (o *LocalOps) Clients(ctx context.Context) ([]adminapi.Client, error) {
	return o.Backend.Clients(ctx)
}

func (o *LocalOps) DisconnectClient(ctx context.Context, name string) error {
	return o.Backend.Disconnect(ctx, name)
}

func (o *LocalOps) Tunnels(ctx context.Context) ([]adminapi.Tunnel, error) {
	return o.Backend.Tunnels(ctx)
}

func (o *LocalOps) CloseTunnel(ctx context.Context, id string) error {
	return o.Backend.CloseTunnel(ctx, id)
}

// RequestTunnel asks the client to open the tunnel through Backend.RequestTunnel, which checks the client's token
// and waits for its answer. Refusals are *adminapi.RemoteError (code and text go to the model); an offline client is
// adminapi.ErrNotFound.
func (o *LocalOps) RequestTunnel(ctx context.Context, p RequestTunnelParams) (RequestTunnelResult, error) {
	t, err := o.Backend.RequestTunnel(ctx, p.Client, adminapi.RemoteOpen{
		Kind: p.Kind, LocalAddr: p.LocalAddr, Name: p.Name, Private: p.Private, RequestedBy: callerFrom(ctx).actor,
	})
	if err != nil {
		return RequestTunnelResult{}, err
	}
	return RequestTunnelResult{Tunnel: t}, nil
}

func (o *LocalOps) Tokens(ctx context.Context) ([]adminapi.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	toks, err := o.Store.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]adminapi.Token, 0, len(toks))
	for _, t := range toks {
		out = append(out, adminapi.Token{
			ID: t.ID, Name: t.Name, Last4: t.Last4, Scopes: nonNil(t.Scopes), MaxTunnels: t.MaxTunnels,
			CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, LastUsedAt: t.LastUsedAt,
			RemoteControl: t.RemoteControl,
		})
	}
	return out, nil
}

func (o *LocalOps) RevokeToken(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	// By id only: Store.RevokeToken also accepts names, which the tools do not.
	if _, err := o.Store.GetToken(ctx, id); err != nil {
		return err
	}
	return o.Store.RevokeToken(ctx, id, o.now())
}

// CreateJoinLink stores a one-time join code through adminapi.CreateJoin, the code behind POST join, so that the
// validation, the scope limits and the link format are the API's. The caller of the tool may grant only the scopes
// it holds (besides the tunnel and connect scopes).
func (o *LocalOps) CreateJoinLink(ctx context.Context, p JoinLinkParams) (JoinLink, error) {
	if o.ServerURL == "" {
		return JoinLink{}, errors.New("join links need the server's public URL, which is not configured")
	}
	c := callerFrom(ctx)
	req := adminapi.JoinRequest{ClientName: p.Client, Scopes: p.Scopes, RemoteControl: &p.AllowRemote}
	if p.TTL > 0 {
		req.TTL = p.TTL.String()
	}
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	jc, err := adminapi.CreateJoin(ctx, o.Store, o.ServerURL, o.now(),
		adminapi.Grantor{Actor: c.actor, Trusted: c.trusted, Scopes: c.scopes}, req)
	if err != nil {
		return JoinLink{}, err
	}
	return JoinLink{URL: jc.Link, Command: jc.Command, Client: jc.ClientName, ExpiresAt: jc.ExpiresAt}, nil
}

func (o *LocalOps) QueryRequests(_ context.Context, q RequestQuery) (RequestsResult, error) {
	f := requestFilter(q)
	reqs := o.Traffic.Requests().Query(f)
	res := RequestsResult{Requests: make([]Request, 0, len(reqs))}
	for i := range reqs {
		res.Requests = append(res.Requests, requestDTO(&reqs[i]))
	}
	if q.Aggregate {
		a := aggregatesDTO(o.Traffic.Requests().Aggregate(f, q.TopN))
		res.Aggregates = &a
	}
	return res, nil
}

func (o *LocalOps) GetRequest(_ context.Context, id uint64) (Request, error) {
	r, ok := o.Traffic.Requests().Get(id)
	if !ok {
		return Request{}, adminapi.ErrNotFound
	}
	return requestDTO(&r), nil
}

// ReplayRequest replays through Backend.ReplayRequest: unknown ids are adminapi.ErrNotFound, requests that cannot be
// replayed (not inspected, body truncated, tunnel offline) are *adminapi.ConflictError.
func (o *LocalOps) ReplayRequest(ctx context.Context, id uint64) (Request, error) {
	r, err := o.Backend.ReplayRequest(ctx, id)
	if err != nil {
		return Request{}, err
	}
	return requestDTO(&r), nil
}

func (o *LocalOps) ConnectionLog(_ context.Context, q ConnQuery) ([]Conn, error) {
	return connsDTO(o.Traffic.Conns().Query(connFilter(q))), nil
}

func (o *LocalOps) GatewayAuthFailures(_ context.Context, since time.Time, limit int) ([]Conn, error) {
	return connsDTO(o.Traffic.AuthFailures(since, limit)), nil
}

func (o *LocalOps) AuditLog(ctx context.Context, limit int) ([]adminapi.AuditEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	es, err := o.Store.ListAudit(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]adminapi.AuditEntry, 0, len(es))
	for _, e := range es {
		out = append(out, adminapi.AuditEntry{ID: e.ID, At: e.At, Actor: e.Actor, Action: e.Action, Target: e.Target, Args: e.Args, Result: e.Result})
	}
	return out, nil
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func requestDTO(r *traffic.Request) Request {
	return Request{
		ID: r.ID, Time: r.Time, TunnelID: r.TunnelID, Tunnel: r.Tunnel, Client: r.Client, VisitorIP: r.VisitorIP,
		Method: r.Method, Host: r.Host, Path: r.Path, Query: r.Query, Status: r.Status, LatencyMS: ms(r.Latency),
		BytesIn: r.BytesIn, BytesOut: r.BytesOut, UserAgent: r.UserAgent, Referer: r.Referer,
		ReplayOf: r.ReplayOf, HasDetail: r.HasDetail, Detail: detailDTO(r.Detail),
	}
}

func connsDTO(cs []traffic.Conn) []Conn {
	out := make([]Conn, 0, len(cs))
	for i := range cs {
		c := &cs[i]
		out = append(out, Conn{
			ID: c.ID, Start: c.Start, DurationMS: ms(c.Duration), TunnelID: c.TunnelID, Tunnel: c.Tunnel, Client: c.Client,
			Kind: c.Kind, VisitorIP: c.VisitorIP, BytesIn: c.BytesIn, BytesOut: c.BytesOut, Outcome: c.Outcome,
		})
	}
	return out
}

func aggregatesDTO(a traffic.Aggregates) Aggregates {
	counts := func(cs []traffic.Count) []Count {
		out := make([]Count, 0, len(cs))
		for _, c := range cs {
			out = append(out, Count{Key: c.Key, Count: c.Count})
		}
		return out
	}
	buckets := make([]Bucket, 0, len(a.PerMinute))
	for _, b := range a.PerMinute {
		buckets = append(buckets, Bucket{Minute: b.Minute, Count: b.Count})
	}
	classes := a.StatusClasses
	if classes == nil {
		classes = map[string]int{}
	}
	return Aggregates{
		Total: a.Total, StatusClasses: classes, TopPaths: counts(a.TopPaths), TopVisitors: counts(a.TopVisitors),
		LatencyMS: Latency{P50: ms(a.Latency.P50), P90: ms(a.Latency.P90), P99: ms(a.Latency.P99)}, PerMinute: buckets,
	}
}

func requestFilter(q RequestQuery) traffic.RequestFilter {
	return traffic.RequestFilter{
		Tunnel: q.Tunnel, Client: q.Client, StatusClass: q.StatusClass, PathPrefix: q.PathPrefix, IP: q.IP,
		Since: q.Since, Limit: q.Limit,
	}
}

func connFilter(q ConnQuery) traffic.ConnFilter {
	return traffic.ConnFilter{
		Tunnel: q.Tunnel, Client: q.Client, Kind: q.Kind, IP: q.IP, Outcome: q.Outcome, Since: q.Since, Limit: q.Limit,
	}
}

func detailDTO(d *traffic.Detail) *RequestDetail {
	if d == nil {
		return nil
	}
	return &RequestDetail{
		RequestHeaders: nonNilHeader(d.RequestHeaders), RequestBody: bodyDTO(d.RequestBody),
		ResponseHeaders: nonNilHeader(d.ResponseHeaders), ResponseBody: bodyDTO(d.ResponseBody),
	}
}

// bodyDTO reuses the JSON form of traffic.Body, which decides between text and base64.
func bodyDTO(b traffic.Body) Body {
	var out Body
	if raw, err := json.Marshal(b); err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func nonNilHeader(h http.Header) http.Header {
	if h == nil {
		return http.Header{}
	}
	return h
}
