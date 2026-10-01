// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package traffic

import (
	"time"
)

// Connection kinds.
const (
	KindTCP = "tcp"
	KindSSH = "ssh"
)

// Connection outcomes.
const (
	OutcomeOK         = "ok"
	OutcomeRefused    = "refused"     // the target is unknown, forbidden or its client did not answer
	OutcomeAuthFailed = "auth_failed" // wrong or missing gateway credentials
	OutcomeLimit      = "limit"       // a connection limit or the failed-attempt limiter turned it away
)

// Conn is one TCP tunnel connection or SSH gateway channel (or a refused/failed attempt). Payload is never
// recorded: SSH is end-to-end encrypted and TCP is opaque.
type Conn struct {
	ID        uint64        `json:"id"`
	Start     time.Time     `json:"start"`
	Duration  time.Duration `json:"duration_ns"`
	TunnelID  string        `json:"tunnel_id,omitempty"` // empty when no tunnel was reached
	Tunnel    string        `json:"tunnel,omitempty"`    // tunnel name, or the requested target when refused
	Client    string        `json:"client,omitempty"`
	Kind      string        `json:"kind"`
	VisitorIP string        `json:"visitor_ip"`
	BytesIn   int64         `json:"bytes_in"`  // visitor to tunnel
	BytesOut  int64         `json:"bytes_out"` // tunnel to visitor
	Outcome   string        `json:"outcome"`
}

// ConnFilter selects connections. Zero fields match everything.
type ConnFilter struct {
	Tunnel  string    // tunnel id or name
	Client  string    // client name
	Kind    string    // KindTCP or KindSSH
	IP      string    // visitor IP, exact
	Outcome string    // one of the Outcome constants
	Since   time.Time // only connections that started at or after this time
	Limit   int       // 0 is DefaultLimit, capped at MaxLimit
}

// Match reports whether c passes the filter (Limit is not considered).
func (f ConnFilter) Match(c *Conn) bool {
	switch {
	case f.Tunnel != "" && f.Tunnel != c.TunnelID && f.Tunnel != c.Tunnel:
		return false
	case f.Client != "" && f.Client != c.Client:
		return false
	case f.Kind != "" && f.Kind != c.Kind:
		return false
	case f.IP != "" && f.IP != c.VisitorIP:
		return false
	case f.Outcome != "" && f.Outcome != c.Outcome:
		return false
	case !f.Since.IsZero() && c.Start.Before(f.Since):
		return false
	}
	return true
}

// Conns is the thread-safe ring buffer of Conn entries.
type Conns struct{ r *ring[Conn] }

// NewConns returns a connection journal keeping the last size connections; size <= 0 stores nothing.
func NewConns(size int) *Conns { return &Conns{r: newRing[Conn](size)} }

// Enabled reports whether the journal stores anything (its size is above 0). It is safe on a nil *Conns.
func (q *Conns) Enabled() bool { return q != nil && len(q.r.buf) > 0 }

// Add stores a copy of c with an assigned ID and returns it (0 if the journal is off). Safe on a nil *Conns.
func (q *Conns) Add(c Conn) uint64 {
	if q == nil {
		return 0
	}
	c.Tunnel = clip(c.Tunnel, maxName)
	return q.r.add(func(id uint64) Conn { c.ID = id; return c })
}

// Len returns the number of stored connections.
func (q *Conns) Len() int {
	if q == nil {
		return 0
	}
	return q.r.len()
}

// Query returns the connections matching f, newest first.
func (q *Conns) Query(f ConnFilter) []Conn {
	if q == nil {
		return nil
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	return q.r.collect(f.Match, min(limit, MaxLimit))
}

// Log bundles the two journals of a server. Both are nil-safe: a journal sized 0 is off and records nothing.
type Log struct {
	requests *Requests
	conns    *Conns
}

// NewLog returns a Log with the given capacities; 0 turns the corresponding journal off.
func NewLog(maxRequests, maxConns int) *Log {
	return &Log{requests: NewRequests(maxRequests), conns: NewConns(maxConns)}
}

// Requests returns the request journal (never nil for a Log from NewLog).
func (l *Log) Requests() *Requests {
	if l == nil {
		return nil
	}
	return l.requests
}

// Conns returns the connection journal (never nil for a Log from NewLog).
func (l *Log) Conns() *Conns {
	if l == nil {
		return nil
	}
	return l.conns
}

// AuthFailures returns the connections that failed gateway authentication since the given time (zero for all),
// newest first, at most limit of them (0 is DefaultLimit).
func (l *Log) AuthFailures(since time.Time, limit int) []Conn {
	return l.Conns().Query(ConnFilter{Outcome: OutcomeAuthFailed, Since: since, Limit: limit})
}
