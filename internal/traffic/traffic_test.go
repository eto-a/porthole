// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package traffic

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func TestRingOverwriteAndGet(t *testing.T) {
	q := NewRequests(3)
	for i := 1; i <= 5; i++ {
		if id := q.Add(Request{Path: fmt.Sprintf("/%d", i)}); id != uint64(i) {
			t.Fatalf("id %d, want %d", id, i)
		}
	}
	if q.Len() != 3 {
		t.Fatalf("len %d", q.Len())
	}
	got := q.Query(RequestFilter{})
	if len(got) != 3 || got[0].Path != "/5" || got[1].Path != "/4" || got[2].Path != "/3" {
		t.Fatalf("newest first: %+v", got)
	}
	for id, want := range map[uint64]bool{0: false, 1: false, 2: false, 3: true, 5: true, 6: false} {
		r, ok := q.Get(id)
		if ok != want || (ok && r.ID != id) {
			t.Fatalf("Get(%d) = %+v, %v", id, r, ok)
		}
	}
}

func TestOffAndNil(t *testing.T) {
	off := NewLog(0, 0)
	if off.Requests().Add(Request{}) != 0 || off.Conns().Add(Conn{}) != 0 {
		t.Fatal("a journal of size 0 stored something")
	}
	if len(off.Requests().Query(RequestFilter{})) != 0 || len(off.Conns().Query(ConnFilter{})) != 0 {
		t.Fatal("off journal returned entries")
	}
	var l *Log
	l.Requests().Add(Request{})
	l.Conns().Add(Conn{})
	_ = l.AuthFailures(time.Time{}, 0)
	if l.Requests().Aggregate(RequestFilter{}, 5).Total != 0 {
		t.Fatal("nil aggregate")
	}
}

func TestRequestFilters(t *testing.T) {
	q := NewRequests(100)
	add := func(tun, label, client, ip, path string, status int, at time.Duration) {
		q.Add(Request{
			Time: t0.Add(at), TunnelID: tun, Tunnel: tun + "-name", Label: label, Client: client,
			VisitorIP: ip, Path: path, Status: status,
		})
	}
	add("t1", "blog", "alice", "1.1.1.1", "/", 200, 0)
	add("t1", "blog", "alice", "2.2.2.2", "/wp-admin/x", 404, time.Minute)
	add("t2", "api", "bob", "1.1.1.1", "/v1/users", 502, 2*time.Minute)
	add("t2", "api", "bob", "3.3.3.3", "/v1/items", 200, 3*time.Minute)

	cases := []struct {
		name string
		f    RequestFilter
		want int
	}{
		{"all", RequestFilter{}, 4},
		{"tunnel id", RequestFilter{Tunnel: "t1"}, 2},
		{"tunnel name", RequestFilter{Tunnel: "t2-name"}, 2},
		{"tunnel label", RequestFilter{Tunnel: "api"}, 2},
		{"client", RequestFilter{Client: "alice"}, 2},
		{"status class 2", RequestFilter{StatusClass: 2}, 2},
		{"status class 5", RequestFilter{StatusClass: 5}, 1},
		{"path prefix", RequestFilter{PathPrefix: "/v1/"}, 2},
		{"ip", RequestFilter{IP: "1.1.1.1"}, 2},
		{"since", RequestFilter{Since: t0.Add(2 * time.Minute)}, 2},
		{"combined", RequestFilter{Client: "bob", StatusClass: 2, IP: "3.3.3.3"}, 1},
		{"none", RequestFilter{Client: "carol"}, 0},
		{"limit", RequestFilter{Limit: 3}, 3},
	}
	for _, c := range cases {
		if got := q.Query(c.f); len(got) != c.want {
			t.Errorf("%s: got %d, want %d", c.name, len(got), c.want)
		}
	}
	if got := q.Query(RequestFilter{Limit: 1}); got[0].Path != "/v1/items" {
		t.Fatalf("limit keeps the newest: %+v", got)
	}
}

func TestQueryLimitCap(t *testing.T) {
	q := NewRequests(MaxLimit + 50)
	for range MaxLimit + 50 {
		q.Add(Request{})
	}
	if n := len(q.Query(RequestFilter{})); n != DefaultLimit {
		t.Fatalf("default limit: %d", n)
	}
	if n := len(q.Query(RequestFilter{Limit: 1 << 20})); n != MaxLimit {
		t.Fatalf("capped limit: %d", n)
	}
	if got := q.Aggregate(RequestFilter{Limit: 1}, 3).Total; got != MaxLimit+50 {
		t.Fatalf("aggregate must ignore the limit: %d", got)
	}
}

func TestAggregates(t *testing.T) {
	var reqs []Request
	for i := 1; i <= 100; i++ {
		reqs = append(reqs, Request{
			Time:      t0.Add(time.Duration(i-1) * 3 * time.Second), // 20 per minute, 5 minutes
			Path:      "/p",
			VisitorIP: "9.9.9.9",
			Status:    200,
			Latency:   time.Duration(i) * time.Millisecond,
		})
	}
	reqs = append(reqs,
		Request{Time: t0, Path: "/a", VisitorIP: "1.1.1.1", Status: 404},
		Request{Time: t0, Path: "/a", VisitorIP: "1.1.1.1", Status: 502},
		Request{Time: t0, Path: "/b", VisitorIP: "2.2.2.2", Status: 0},
	)
	a := Summarize(reqs, 2)
	if a.Total != 103 {
		t.Fatalf("total %d", a.Total)
	}
	if a.StatusClasses["2xx"] != 100 || a.StatusClasses["4xx"] != 1 || a.StatusClasses["5xx"] != 1 || a.StatusClasses["other"] != 1 {
		t.Fatalf("classes %v", a.StatusClasses)
	}
	if len(a.TopPaths) != 2 || a.TopPaths[0] != (Count{"/p", 100}) || a.TopPaths[1] != (Count{"/a", 2}) {
		t.Fatalf("top paths %+v", a.TopPaths)
	}
	if len(a.TopVisitors) != 2 || a.TopVisitors[0].Key != "9.9.9.9" || a.TopVisitors[1] != (Count{"1.1.1.1", 2}) {
		t.Fatalf("top visitors %+v", a.TopVisitors)
	}
	if len(a.PerMinute) != 5 || a.PerMinute[0].Count != 23 || a.PerMinute[1].Count != 20 || !a.PerMinute[0].Minute.Before(a.PerMinute[1].Minute) {
		t.Fatalf("per minute %+v", a.PerMinute)
	}

	lat := LatencyPercentiles(reqs[:100])
	if lat.P50 != 50*time.Millisecond || lat.P90 != 90*time.Millisecond || lat.P99 != 99*time.Millisecond {
		t.Fatalf("percentiles %+v", lat)
	}
	if (LatencyPercentiles(nil) != Percentiles{}) {
		t.Fatal("empty percentiles")
	}
	one := LatencyPercentiles([]Request{{Latency: time.Second}})
	if one.P50 != time.Second || one.P99 != time.Second {
		t.Fatalf("single sample %+v", one)
	}
}

func TestMaskQuery(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // test data, not credentials
		"":                           "",
		"a=1&b=2":                    "a=1&b=2",
		"token=abc&x=1":              "token=REDACTED&x=1",
		"x=1&API_KEY=s3&y":           "x=1&API_KEY=REDACTED&y",
		"password=p%40ss&secret=":    "password=REDACTED&secret=REDACTED",
		"Auth=1&access%5Ftoken=2":    "Auth=REDACTED&access%5Ftoken=REDACTED",
		"q=token&monkey=1&page=2":    "q=token&monkey=REDACTED&page=2",
		"authorization":              "authorization",
		"a=1;token=2":                "a=1;token=2", // ';' is not a separator for net/http
		"passwd=1&keyword=go&tok=ok": "passwd=REDACTED&keyword=REDACTED&tok=ok",
	}
	for in, want := range cases {
		if got := MaskQuery(in); got != want {
			t.Errorf("MaskQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAddMasksAndClips(t *testing.T) {
	q := NewRequests(2)
	q.Add(Request{
		Query:     "token=abc&x=1",
		Referer:   "https://a.example/p?key=zzz&y=2#frag",
		UserAgent: strings.Repeat("u", 5000),
		Path:      strings.Repeat("é", 3000),
	})
	r, _ := q.Get(1)
	if r.Query != "token=REDACTED&x=1" || r.Referer != "https://a.example/p?key=REDACTED&y=2" {
		t.Fatalf("not masked: %+v", r)
	}
	if len(r.UserAgent) != maxUserAgent || len(r.Path) > maxPath || strings.ContainsRune(r.Path, '�') {
		t.Fatalf("not clipped: ua=%d path=%d", len(r.UserAgent), len(r.Path))
	}
}

func TestConns(t *testing.T) {
	l := NewLog(1, 3)
	l.Conns().Add(Conn{Start: t0, Kind: KindTCP, VisitorIP: "1.1.1.1", Outcome: OutcomeOK, TunnelID: "t1", Client: "a"})
	l.Conns().Add(Conn{Start: t0.Add(time.Minute), Kind: KindSSH, VisitorIP: "2.2.2.2", Outcome: OutcomeAuthFailed})
	l.Conns().Add(Conn{Start: t0.Add(2 * time.Minute), Kind: KindSSH, VisitorIP: "2.2.2.2", Outcome: OutcomeAuthFailed})
	l.Conns().Add(Conn{Start: t0.Add(3 * time.Minute), Kind: KindSSH, VisitorIP: "3.3.3.3", Outcome: OutcomeRefused})
	if got := l.Conns().Len(); got != 3 {
		t.Fatalf("len %d", got)
	}
	if got := l.Conns().Query(ConnFilter{Kind: KindTCP}); len(got) != 0 {
		t.Fatalf("oldest must be evicted: %+v", got)
	}
	if got := l.AuthFailures(time.Time{}, 0); len(got) != 2 || got[0].Start.Before(got[1].Start) {
		t.Fatalf("auth failures newest first: %+v", got)
	}
	if got := l.AuthFailures(t0.Add(2*time.Minute), 0); len(got) != 1 {
		t.Fatalf("since: %+v", got)
	}
	if got := l.Conns().Query(ConnFilter{IP: "3.3.3.3", Outcome: OutcomeRefused}); len(got) != 1 || got[0].ID != 4 {
		t.Fatalf("ip+outcome: %+v", got)
	}
}

func TestConcurrent(t *testing.T) {
	const writers, each = 8, 500
	q := NewRequests(200)
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				q.Add(Request{Path: fmt.Sprintf("/%d/%d", w, i), Status: 200, Latency: time.Millisecond})
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for range 200 {
				q.Query(RequestFilter{Limit: 50})
				q.Aggregate(RequestFilter{StatusClass: 2}, 3)
				q.Get(1)
			}
		})
	}
	wg.Wait()
	if q.Len() != 200 {
		t.Fatalf("len %d", q.Len())
	}
	got := q.Query(RequestFilter{Limit: MaxLimit})
	for i := 1; i < len(got); i++ {
		if got[i-1].ID != got[i].ID+1 {
			t.Fatalf("ids not consecutive at %d: %d then %d", i, got[i-1].ID, got[i].ID)
		}
	}
	if got[0].ID != writers*each {
		t.Fatalf("newest id %d", got[0].ID)
	}
}
