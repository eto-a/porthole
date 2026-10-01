// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/traffic"
)

// testSocketClient returns a SocketClient that talks to the API's socket handler over TCP, so that the tests run
// on every platform.
func testSocketClient(t *testing.T, e *env) *SocketClient {
	t.Helper()
	ts := httptest.NewServer(e.api.SocketHandler())
	t.Cleanup(ts.Close)
	return &SocketClient{hc: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", ts.Listener.Addr().String())
			},
		},
	}}
}

func TestSocketClientTraffic(t *testing.T) {
	e := newEnv(t, nil)
	c := testSocketClient(t, e)
	ctx := context.Background()
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	reqs, err := c.Requests(ctx, traffic.RequestFilter{Tunnel: "blog", StatusClass: 4, PathPrefix: "/wp", IP: "1.2.3.4", Since: since, Limit: 5})
	if err != nil || len(reqs) != 2 || reqs[0].ID != 2 {
		t.Fatalf("Requests: %+v, %v", reqs, err)
	}
	if reqs[0].Detail != nil {
		t.Error("the list carries a Detail")
	}
	f := e.be.filter
	if f.Tunnel != "blog" || f.StatusClass != 4 || f.PathPrefix != "/wp" || f.IP != "1.2.3.4" || !f.Since.Equal(since) || f.Limit != 5 {
		t.Errorf("filter at the backend: %+v", f)
	}

	ag, err := c.RequestAggregates(ctx, traffic.RequestFilter{Client: "home"}, 7)
	if err != nil || ag.Total != 7 || e.be.filter.Client != "home" {
		t.Fatalf("RequestAggregates: %+v, %v (filter %+v)", ag, err, e.be.filter)
	}

	r, err := c.Request(ctx, 7)
	if err != nil || r.ID != 7 || r.Detail == nil || string(r.Detail.ResponseBody.Data) != "secret body" {
		t.Fatalf("Request: %+v, %v", r, err)
	}
	var apiErr *Error
	if _, err := c.Request(ctx, 99); !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
		t.Errorf("unknown request: %v", err)
	}

	rep, err := c.ReplayRequest(ctx, 7)
	if err != nil || rep.ID != 70 || rep.ReplayOf != 7 {
		t.Fatalf("ReplayRequest: %+v, %v", rep, err)
	}
	if _, err := c.ReplayRequest(ctx, 8); !errors.As(err, &apiErr) || apiErr.Code != "conflict" {
		t.Errorf("replay of a request that cannot be replayed: %v", err)
	}

	cs, err := c.Connections(ctx, traffic.ConnFilter{Kind: "ssh", Outcome: "limit"})
	if err != nil || len(cs) != 1 || cs[0].Kind != "ssh" || cs[0].Outcome != "limit" {
		t.Fatalf("Connections: %+v, %v", cs, err)
	}
	fs, err := c.AuthFailures(ctx, since, 9)
	if err != nil || len(fs) != 1 || fs[0].Duration != 9 {
		t.Fatalf("AuthFailures: %+v, %v", fs, err)
	}
}
