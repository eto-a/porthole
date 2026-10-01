// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package traffic

import (
	"cmp"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultSize is the default capacity of each journal.
const DefaultSize = 10000

// Query limits: a Limit of 0 means DefaultLimit, and no Limit exceeds MaxLimit.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Request is one proxied HTTP request. Bytes count body bytes only (no headers). For a WebSocket upgrade the
// status is 101, Latency is the time until the upgrade and the bytes are those carried after it.
type Request struct {
	ID        uint64        `json:"id"`
	Time      time.Time     `json:"time"` // when the request arrived
	TunnelID  string        `json:"tunnel_id"`
	Tunnel    string        `json:"tunnel"` // tunnel name
	Label     string        `json:"label"`  // DNS label of the HTTP tunnel
	Client    string        `json:"client"`
	VisitorIP string        `json:"visitor_ip"`
	Method    string        `json:"method"`
	Host      string        `json:"host"`
	Path      string        `json:"path"`
	Query     string        `json:"query,omitempty"` // values of token, key, password, secret, auth parameters masked
	Status    int           `json:"status"`
	Latency   time.Duration `json:"latency_ns"`
	BytesIn   int64         `json:"bytes_in"`  // request body, visitor to tunnel
	BytesOut  int64         `json:"bytes_out"` // response body, tunnel to visitor
	UserAgent string        `json:"user_agent,omitempty"`
	Referer   string        `json:"referer,omitempty"` // query masked, fragment dropped

	// ReplayOf is the id of the request this one replays (0 for a real visitor request).
	ReplayOf uint64 `json:"replay_of,omitempty"`
	// HasDetail reports that the request was inspected and its Detail is still kept.
	HasDetail bool `json:"has_detail,omitempty"`
	// Detail holds headers and bodies of an inspected request. Only Get returns it; Query and Aggregate leave
	// it nil. It is nil for requests of tunnels that are not inspected and after the detail budget evicted it.
	Detail *Detail `json:"detail,omitempty"`
}

// RequestFilter selects requests. Zero fields match everything.
type RequestFilter struct {
	Tunnel      string    // tunnel id, name or label
	Client      string    // client name
	StatusClass int       // 1..5 for 1xx..5xx
	PathPrefix  string    // prefix of the path
	IP          string    // visitor IP, exact
	Since       time.Time // only requests at or after this time
	Limit       int       // result size for Query: 0 is DefaultLimit, capped at MaxLimit; ignored by Aggregate
}

// Match reports whether r passes the filter (Limit is not considered).
func (f RequestFilter) Match(r *Request) bool {
	switch {
	case f.Tunnel != "" && f.Tunnel != r.TunnelID && f.Tunnel != r.Tunnel && f.Tunnel != r.Label:
		return false
	case f.Client != "" && f.Client != r.Client:
		return false
	case f.StatusClass != 0 && f.StatusClass != r.Status/100:
		return false
	case f.PathPrefix != "" && !strings.HasPrefix(r.Path, f.PathPrefix):
		return false
	case f.IP != "" && f.IP != r.VisitorIP:
		return false
	case !f.Since.IsZero() && r.Time.Before(f.Since):
		return false
	}
	return true
}

// Requests is the thread-safe ring buffer of Request entries.
type Requests struct {
	r *ring[Request]

	maxDetail atomic.Int64 // budget of Detail memory, see SetMaxDetailBytes
	// The fields below are guarded by r.mu.
	detailBytes int64
	detailIDs   []uint64 // ids of the entries that hold a Detail, oldest first
	detailHead  int      // detailIDs[:detailHead] are already gone
}

// NewRequests returns a request journal keeping the last size requests; size <= 0 stores nothing. Details of
// inspected requests are limited to DefaultMaxDetailBytes until SetMaxDetailBytes says otherwise.
func NewRequests(size int) *Requests {
	q := &Requests{r: newRing[Request](size)}
	q.maxDetail.Store(DefaultMaxDetailBytes)
	q.r.onEvict = q.evicting
	q.r.afterAdd = q.trimDetails
	return q
}

// DefaultMaxDetailBytes is the default budget of Detail memory: 64 MiB.
const DefaultMaxDetailBytes = 64 << 20

// SetMaxDetailBytes sets the memory budget of stored details (headers and bodies of inspected requests). When it
// is exceeded the details of the oldest requests are dropped; their metadata stays. 0 stores no details. It is
// safe on a nil *Requests.
func (q *Requests) SetMaxDetailBytes(n int64) {
	if q != nil {
		q.maxDetail.Store(max(n, 0))
	}
}

// DetailBytes returns the memory currently charged for stored details.
func (q *Requests) DetailBytes() int64 {
	if q == nil {
		return 0
	}
	q.r.mu.RLock()
	defer q.r.mu.RUnlock()
	return q.detailBytes
}

// evicting runs under the ring lock before an entry is overwritten. A stored detail is always the oldest one.
func (q *Requests) evicting(old *Request) {
	if old.Detail == nil {
		return
	}
	q.detailBytes -= old.Detail.size
	q.detailHead++
	q.compact()
}

// trimDetails runs under the ring lock after an add and drops the oldest details until the budget holds.
func (q *Requests) trimDetails() {
	limit := q.maxDetail.Load()
	for q.detailBytes > limit && q.detailHead < len(q.detailIDs) {
		e := q.r.at(q.detailIDs[q.detailHead])
		q.detailHead++
		if e == nil || e.Detail == nil {
			continue
		}
		q.detailBytes -= e.Detail.size
		e.Detail, e.HasDetail = nil, false
	}
	q.compact()
}

func (q *Requests) compact() {
	if q.detailHead > 64 && q.detailHead*2 > len(q.detailIDs) {
		q.detailIDs = append(q.detailIDs[:0], q.detailIDs[q.detailHead:]...)
		q.detailHead = 0
	}
}

// Enabled reports whether the journal stores anything (its size is above 0). Callers use it to skip the work of
// building entries. It is safe on a nil *Requests.
func (q *Requests) Enabled() bool { return q != nil && len(q.r.buf) > 0 }

// Add stores a copy of req with an assigned ID, masking the query and clipping long fields, and returns the ID
// (0 if the journal is off). It is safe on a nil *Requests.
func (q *Requests) Add(req Request) uint64 {
	if q == nil {
		return 0
	}
	det := req.Detail
	req.Host = clip(req.Host, maxHost)
	req.Tunnel = clip(req.Tunnel, maxName)
	req.Path = clip(req.Path, maxPath)
	req.Query = clip(MaskQuery(req.Query), maxQuery)
	req.UserAgent = clip(req.UserAgent, maxUserAgent)
	req.Referer = clip(maskURL(req.Referer), maxReferer)
	req.Detail, req.HasDetail = nil, false
	var d *Detail
	if det != nil {
		if p := det.prepared(); p.size <= q.maxDetail.Load() {
			d = p
		}
	}
	return q.r.add(func(id uint64) Request {
		req.ID = id
		if d != nil {
			req.Detail, req.HasDetail = d, true
			q.detailBytes += d.size
			q.detailIDs = append(q.detailIDs, id)
		}
		return req
	})
}

// Get returns the request with the given ID while it is still in the buffer.
func (q *Requests) Get(id uint64) (Request, bool) {
	if q == nil {
		return Request{}, false
	}
	return q.r.get(id)
}

// Len returns the number of stored requests.
func (q *Requests) Len() int {
	if q == nil {
		return 0
	}
	return q.r.len()
}

// Query returns the requests matching f, newest first.
func (q *Requests) Query(f RequestFilter) []Request {
	if q == nil {
		return nil
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	out := q.r.collect(f.Match, min(limit, MaxLimit))
	for i := range out {
		out[i].Detail = nil
	}
	return out
}

// Aggregate summarises every request matching f (Limit is ignored); top lists hold at most topN entries.
func (q *Requests) Aggregate(f RequestFilter, topN int) Aggregates {
	if q == nil {
		return Aggregates{}
	}
	return Summarize(q.r.collect(f.Match, 0), topN)
}

// Count is a key with the number of requests that had it.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Percentiles are latency percentiles (nearest rank).
type Percentiles struct {
	P50 time.Duration `json:"p50_ns"`
	P90 time.Duration `json:"p90_ns"`
	P99 time.Duration `json:"p99_ns"`
}

// Bucket is the number of requests that arrived in one minute.
type Bucket struct {
	Minute time.Time `json:"minute"` // start of the minute, UTC
	Count  int       `json:"count"`
}

// Aggregates summarises a set of requests.
type Aggregates struct {
	Total         int            `json:"total"`
	StatusClasses map[string]int `json:"status_classes"` // "2xx", "4xx", ...; only classes that occurred
	TopPaths      []Count        `json:"top_paths"`
	TopVisitors   []Count        `json:"top_visitors"`
	Latency       Percentiles    `json:"latency"`
	PerMinute     []Bucket       `json:"per_minute"` // oldest first, minutes without requests are omitted
}

// Summarize computes the aggregates of reqs.
func Summarize(reqs []Request, topN int) Aggregates {
	return Aggregates{
		Total:         len(reqs),
		StatusClasses: StatusClasses(reqs),
		TopPaths:      TopPaths(reqs, topN),
		TopVisitors:   TopVisitors(reqs, topN),
		Latency:       LatencyPercentiles(reqs),
		PerMinute:     PerMinute(reqs),
	}
}

// StatusClasses counts requests per status class ("2xx"). Status 0 (nothing was sent) counts as "other".
func StatusClasses(reqs []Request) map[string]int {
	out := make(map[string]int)
	for i := range reqs {
		c := reqs[i].Status / 100
		if c < 1 || c > 5 {
			out["other"]++
			continue
		}
		out[string(rune('0'+c))+"xx"]++
	}
	return out
}

// TopPaths returns the n most requested paths (query excluded), most frequent first, ties by path.
func TopPaths(reqs []Request, n int) []Count {
	return top(reqs, n, func(r *Request) string { return r.Path })
}

// TopVisitors returns the n visitor IPs with the most requests, most frequent first, ties by IP.
func TopVisitors(reqs []Request, n int) []Count {
	return top(reqs, n, func(r *Request) string { return r.VisitorIP })
}

func top(reqs []Request, n int, key func(*Request) string) []Count {
	counts := make(map[string]int)
	for i := range reqs {
		counts[key(&reqs[i])]++
	}
	out := make([]Count, 0, len(counts))
	for k, c := range counts {
		out = append(out, Count{Key: k, Count: c})
	}
	slices.SortFunc(out, func(a, b Count) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Key, b.Key))
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// LatencyPercentiles returns the p50, p90 and p99 latency by the nearest-rank method; zero for no requests.
func LatencyPercentiles(reqs []Request) Percentiles {
	if len(reqs) == 0 {
		return Percentiles{}
	}
	d := make([]time.Duration, len(reqs))
	for i := range reqs {
		d[i] = reqs[i].Latency
	}
	slices.Sort(d)
	at := func(p int) time.Duration {
		rank := (p*len(d) + 99) / 100 // ceiling of p percent of n
		return d[max(rank, 1)-1]
	}
	return Percentiles{P50: at(50), P90: at(90), P99: at(99)}
}

// PerMinute counts requests per calendar minute (UTC), oldest first; minutes without requests are omitted.
func PerMinute(reqs []Request) []Bucket {
	counts := make(map[int64]int)
	for i := range reqs {
		counts[reqs[i].Time.Unix()/60]++
	}
	out := make([]Bucket, 0, len(counts))
	for m, c := range counts {
		out = append(out, Bucket{Minute: time.Unix(m*60, 0).UTC(), Count: c})
	}
	slices.SortFunc(out, func(a, b Bucket) int { return a.Minute.Compare(b.Minute) })
	return out
}
