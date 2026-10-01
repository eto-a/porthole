// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/traffic"
)

// defaultTopN is the length of the top lists of an aggregate when the caller does not ask for another.
const defaultTopN = 10

// mountTraffic registers the traffic analysis endpoints (ADR 0005, "Observability and traffic analysis").
func (a *API) mountTraffic() {
	p := Prefix
	a.read("GET "+p+"/requests", auth.ScopeAdminRead, a.listRequests)
	a.read("GET "+p+"/requests/{id}", auth.ScopeAdminRead, a.getRequest)
	a.mutateValue("POST "+p+"/requests/{id}/replay", auth.ScopeAdminTraffic, "request.replay", "id",
		func(ctx context.Context, target string) (any, error) {
			id, err := parseID(target)
			if err != nil {
				return nil, err
			}
			return a.be.ReplayRequest(ctx, id)
		})
	a.read("GET "+p+"/connections", auth.ScopeAdminRead, a.listConnections)
	a.read("GET "+p+"/auth-failures", auth.ScopeAdminRead, a.listAuthFailures)
}

func (a *API) listRequests(ctx context.Context, r *http.Request) (any, error) {
	q := r.URL.Query()
	f := traffic.RequestFilter{Tunnel: q.Get("tunnel"), Client: q.Get("client"), PathPrefix: q.Get("path_prefix"), IP: q.Get("ip")}
	var err error
	if f.StatusClass, err = intParam(q, "status_class", 0, 5); err != nil {
		return nil, err
	}
	if f.Since, err = sinceParam(q, a.now()); err != nil {
		return nil, err
	}
	if f.Limit, err = intParam(q, "limit", 0, traffic.MaxLimit); err != nil {
		return nil, err
	}
	if v := q.Get("aggregate"); v == "1" || v == "true" {
		topN, err := intParam(q, "top", 0, traffic.MaxLimit)
		if err != nil {
			return nil, err
		}
		if topN == 0 {
			topN = defaultTopN
		}
		ag, err := a.be.RequestAggregates(ctx, f, topN)
		return map[string]any{"aggregates": ag}, err
	}
	rs, err := a.be.Requests(ctx, f)
	for i := range rs {
		rs[i].Detail = nil
	}
	return map[string]any{"requests": nonNil(rs)}, err
}

// getRequest returns one request. Headers and bodies need the admin:traffic scope: they carry what the visitors
// sent, which the plain request log never does.
func (a *API) getRequest(ctx context.Context, r *http.Request) (any, error) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	req, err := a.be.Request(ctx, id)
	if err != nil {
		return nil, err
	}
	if !principalOf(r).allows(auth.ScopeAdminTraffic) {
		req.Detail = nil
	}
	return req, nil
}

func (a *API) listConnections(ctx context.Context, r *http.Request) (any, error) {
	q := r.URL.Query()
	f := traffic.ConnFilter{
		Tunnel: q.Get("tunnel"), Client: q.Get("client"), Kind: q.Get("kind"), IP: q.Get("ip"), Outcome: q.Get("outcome"),
	}
	var err error
	if f.Since, err = sinceParam(q, a.now()); err != nil {
		return nil, err
	}
	if f.Limit, err = intParam(q, "limit", 0, traffic.MaxLimit); err != nil {
		return nil, err
	}
	cs, err := a.be.Connections(ctx, f)
	return map[string]any{"connections": nonNil(cs)}, err
}

func (a *API) listAuthFailures(ctx context.Context, r *http.Request) (any, error) {
	q := r.URL.Query()
	since, err := sinceParam(q, a.now())
	if err != nil {
		return nil, err
	}
	limit, err := intParam(q, "limit", 0, traffic.MaxLimit)
	if err != nil {
		return nil, err
	}
	cs, err := a.be.AuthFailures(ctx, since, limit)
	return map[string]any{"auth_failures": nonNil(cs)}, err
}

func parseID(s string) (uint64, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil || id == 0 {
		return 0, errBadRequest("request id must be a positive integer")
	}
	return id, nil
}

// intParam reads an optional integer query parameter in [lo, hi].
func intParam(q url.Values, name string, lo, hi int) (int, error) {
	v := q.Get(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, errBadRequest(name + " must be an integer from " + strconv.Itoa(lo) + " to " + strconv.Itoa(hi))
	}
	return n, nil
}

// sinceParam reads the optional "since" parameter: an RFC 3339 time or a duration back from now ("15m").
func sinceParam(q url.Values, now time.Time) (time.Time, error) {
	v := q.Get("since")
	if v == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(v); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, errBadRequest("since must be an RFC 3339 time or a duration such as 15m")
	}
	return t, nil
}
