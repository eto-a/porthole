// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

// reservation remembers the public port a TCP tunnel had, so that its client gets it back (DESIGN.md §3.4).
type reservation struct {
	client string
	port   int
	at     time.Time // when the tunnel went away
}

// minReservationsPerClient is the floor of the number of released ports remembered per client.
const minReservationsPerClient = 8

// loadReservations fills the in-memory reservations from the store, so that after a restart clients get their old
// ports back. Reservations are a convenience: a store failure is logged and the server starts with none. Ports
// outside the configured range are ignored. It runs from New, before the server is shared.
func (s *Server) loadReservations() {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	rs, err := s.store.LoadPortReservations(ctx, s.now(), reservationTTL)
	if err != nil {
		s.log.Warn("cannot load port reservations; tunnels may get new ports", "err", err)
		return
	}
	for _, r := range rs {
		if r.Port < s.portLo || r.Port > s.portHi {
			continue
		}
		s.reserved[reservationKey(r.Client, r.Tunnel)] = reservation{client: r.Client, port: r.Port, at: r.ReleasedAt}
	}
	s.log.Info("port reservations loaded", "loaded", len(s.reserved), "stored", len(rs))
}

// holdPort queues the persistence of the port of a live tunnel. Called with Server.mu held: it only queues, the
// write itself runs on the persister after the lock is gone (see persister). A failure is only logged, because the
// reservation is not a condition for the tunnel.
func (s *Server) holdPort(client, tunnel string, port int) {
	now := s.now()
	s.persist.add(func(ctx context.Context) {
		if err := s.store.HoldPort(ctx, client, tunnel, port, now, reservationTTL); err != nil {
			s.log.Warn("cannot persist port reservation", "client", client, "tunnel", tunnel, "port", port, "err", err)
		}
	})
}

// releasePort queues the start of the persisted reservation period of a closed tunnel. Same rules as holdPort.
func (s *Server) releasePort(client, tunnel string, at time.Time) {
	s.persist.add(func(ctx context.Context) {
		if err := s.store.ReleasePort(ctx, client, tunnel, at); err != nil {
			s.log.Warn("cannot persist port release", "client", client, "tunnel", tunnel, "err", err)
		}
	})
}

// claimedLabels returns the addresses of a new tunnel that are claimed for good by the pair (client, name): the
// hostname label of an HTTP tunnel, the gateway address of an ssh tunnel and, for the ssh tunnel named "ssh", the
// bare client name. TCP tunnels have none.
func claimedLabels(client, kind, name, label string) []string {
	switch kind {
	case proto.KindHTTP:
		return []string{label}
	case proto.KindSSH:
		return sshAddrs(client, name)
	}
	return nil
}

// claimLabels makes labels belong to (client, name) in the store before the tunnel is registered, outside
// Server.mu. It returns the labels this call claimed for the first time, so that a registration that then fails can
// take them back. A label that belongs to another pair, or is the name of another client, is name_taken; a client
// that would hold more than limits.max_label_claims_per_client labels gets limit_exceeded, after the claims nobody
// has used for limits.label_claim_ttl are dropped.
func (s *Server) claimLabels(ctx context.Context, c *session, name string, labels []string) ([]string, *proto.Error) {
	if len(labels) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	s.sweepLabelClaims(labelSweepEvery)
	created, err := s.store.ClaimLabels(ctx, c.name, name, labels, s.now(), s.maxClaims)
	if errors.Is(err, store.ErrLabelLimit) && s.sweepLabelClaims(labelForcedSweepEvery) > 0 {
		created, err = s.store.ClaimLabels(ctx, c.name, name, labels, s.now(), s.maxClaims)
	}
	switch {
	case err == nil:
		return created, nil
	case errors.Is(err, store.ErrLabelClaimed):
		c.log.Warn("tunnel name refused: the label is claimed by another client", "name", name, "labels", labels)
		return nil, &proto.Error{Code: proto.CodeNameTaken, Message: "this name is reserved for another client or its tunnel; " +
			"pick another tunnel name (the server operator can free it with `portholed admin release-label`)"}
	case errors.Is(err, store.ErrLabelLimit):
		c.log.Warn("tunnel name refused: too many permanent names", "name", name, "limit", s.maxClaims)
		return nil, &proto.Error{Code: proto.CodeLimitExceeded, Message: fmt.Sprintf("this client already holds the maximum of %d "+
			"permanent tunnel names (names unused for %s are dropped); reuse one of them or ask the server operator "+
			"to free names with `portholed admin release-label`", s.maxClaims, s.claimTTL)}
	default:
		c.log.Error("cannot claim tunnel labels", "name", name, "labels", labels, "err", err)
		return nil, &proto.Error{Code: proto.CodeInternal, Message: "internal error"}
	}
}

// sweepLabelClaims deletes the label claims that have not been used for the claim TTL and returns how many it
// deleted. It does nothing if the last sweep was less than every ago (0: always). The claims of live tunnels are marked as used
// first, so they never expire while the tunnel is online. A store failure is only logged.
func (s *Server) sweepLabelClaims(every time.Duration) int {
	if s.claimTTL <= 0 {
		return 0
	}
	now := s.now()
	last := s.lastSweep.Load()
	if now.UnixNano()-last < int64(every) || !s.lastSweep.CompareAndSwap(last, now.UnixNano()) {
		return 0
	}
	s.mu.Lock()
	var live []store.ClaimOwner
	for _, c := range s.sessions {
		for _, t := range c.tunnels {
			live = append(live, store.ClaimOwner{Client: c.name, Tunnel: t.name})
		}
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	n, err := s.store.ExpireLabelClaims(ctx, now, s.claimTTL, live)
	if err != nil {
		s.log.Warn("cannot expire unused label claims", "err", err)
		return 0
	}
	if n > 0 {
		s.log.Info("unused label claims expired", "count", n, "ttl", s.claimTTL.String())
	}
	return n
}

// unclaimLabels takes back labels claimed for a registration that failed afterwards.
func (s *Server) unclaimLabels(client, tunnel string, labels []string) {
	if len(labels) == 0 {
		return
	}
	s.persist.add(func(ctx context.Context) {
		if err := s.store.UnclaimLabels(ctx, client, tunnel, labels); err != nil {
			s.log.Warn("cannot take back label claims", "client", client, "tunnel", tunnel, "err", err)
		}
	})
}

// tunnel is a registered HTTP or TCP tunnel.
type tunnel struct {
	id      string
	kind    string
	name    string
	nameKey string // key in session.names
	sess    *session
	ctx     context.Context
	cancel  context.CancelFunc

	// HTTP
	label   string
	handler http.Handler
	tr      *http.Transport

	// TCP
	port int
	ln   net.Listener
	sem  chan struct{} // limits concurrent connections (also used by ssh tunnels)

	// HTTP: limits concurrent visitor requests; nil = unlimited
	httpSem chan struct{}

	// SSH
	private bool // the gateway requires a porthole token to reach this tunnel

	// inspect (HTTP) stores bodies and headers of the tunnel's requests in the traffic journal.
	inspect bool
}

// closeTunnel cancels the tunnel's context (which also tears down its in-flight TCP connections) and closes its
// listener. It never blocks, so it is safe to call with Server.mu held. The HTTP transport is released
// separately by releaseTransport, because closing a stream can wait on a stalled connection.
func (t *tunnel) closeTunnel() {
	t.cancel()
	if t.ln != nil {
		_ = t.ln.Close()
	}
}

// releaseTransport closes the idle upstream connections of an HTTP tunnel, off the caller's goroutine so that a
// stalled client cannot hold up a login or the registry. Call it without Server.mu held.
func (s *Server) releaseTransport(ts ...*tunnel) {
	for _, t := range ts {
		if t.tr == nil {
			continue
		}
		if !s.start(t.tr.CloseIdleConnections) {
			t.tr.CloseIdleConnections() // shutting down: Close waits for us anyway
		}
	}
}

// adopt makes c the active session of its client, replacing an older one. The old session's tunnels are released
// synchronously (so the new session can claim the same labels and ports at once), but the old session itself is
// torn down asynchronously: the new login never waits for it (frp#5391).
func (s *Server) adopt(c *session) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("server closed")
	}
	old := s.sessions[c.name]
	s.sessions[c.name] = c
	s.mu.Unlock()

	if old != nil {
		// A thief with a copied token takes the tunnels over exactly like this (the old client is told "session_replaced"
		// and does not retry), so say where the new login came from.
		old.log.Warn("session replaced by a newer login",
			"new_session", c.id, "new_remote", c.remote, "old_remote", old.remote, "same_ip", ipOf(c.remote) == ipOf(old.remote))
		s.releaseAll(old)
		old.kill("replaced by a newer login", &proto.Error{
			Code:    proto.CodeSessionReplaced,
			Message: "this client logged in again from another connection; this session is closed",
		})
	}
	return nil
}

// releaseAll removes c and every tunnel it owns from the registry and closes their listeners and transports.
// It is idempotent. Labels of the removed HTTP tunnels answer 502 for offlineGrace so that a reconnecting client
// does not look like a vanished tunnel.
func (s *Server) releaseAll(c *session) {
	s.mu.Lock()
	c.dead = true
	removed := make([]*tunnel, 0, len(c.tunnels))
	for _, t := range c.tunnels {
		s.removeLocked(t, true)
		removed = append(removed, t)
	}
	if s.sessions[c.name] == c {
		delete(s.sessions, c.name)
	}
	s.mu.Unlock()
	s.releaseTransport(removed...)
}

// removeLocked unregisters t. offline leaves a short-lived "client is offline" marker for its HTTP label.
func (s *Server) removeLocked(t *tunnel, offline bool) {
	now := s.now()
	delete(t.sess.tunnels, t.id)
	delete(t.sess.names, t.nameKey)
	switch t.kind {
	case proto.KindHTTP:
		if s.labels[t.label] == t {
			delete(s.labels, t.label)
		}
		if offline {
			s.sweepOfflineLocked(now)
			s.offline[t.label] = now.Add(offlineGrace)
			s.holdLocked(addrKey(proto.KindHTTP, t.label), reservationKey(t.sess.name, t.name), now)
		}
	case proto.KindSSH:
		label := sshLabel(t.sess.name, t.name)
		if s.sshLabels[label] == t {
			delete(s.sshLabels, label)
		}
		if offline {
			s.sweepOfflineLocked(now)
			for _, a := range sshAddrs(t.sess.name, t.name) {
				s.holdLocked(addrKey(proto.KindSSH, a), reservationKey(t.sess.name, t.name), now)
			}
		}
	case proto.KindTCP:
		if s.ports[t.port] == t {
			delete(s.ports, t.port)
		}
		s.reserved[reservationKey(t.sess.name, t.name)] = reservation{client: t.sess.name, port: t.port, at: now}
		s.releasePort(t.sess.name, t.name, now)
		s.trimReservationsLocked(t.sess.name, now)
	}
	t.closeTunnel()
}

func (s *Server) sweepOfflineLocked(now time.Time) {
	s.sweepHeldLocked(now)
	for l, exp := range s.offline {
		if !now.Before(exp) {
			delete(s.offline, l)
		}
	}
}

func reservationKey(client, tunnel string) string { return client + "/" + tunnel }

// trimReservationsLocked keeps at most max(minReservationsPerClient, 2*max_tunnels_per_client) remembered ports for
// client, so that a client that cycles through TCP names cannot hold the whole port range for reservationTTL. The
// oldest reservations go first, in memory and in the store (released far enough in the past to be expired there).
func (s *Server) trimReservationsLocked(client string, now time.Time) {
	limit := max(minReservationsPerClient, 2*s.cfg.MaxTunnelsPerClient)
	var mine []string
	for k, r := range s.reserved {
		if r.client == client {
			mine = append(mine, k)
		}
	}
	if len(mine) <= limit {
		return
	}
	slices.SortFunc(mine, func(a, b string) int { return s.reserved[a].at.Compare(s.reserved[b].at) })
	for _, k := range mine[:len(mine)-limit] {
		delete(s.reserved, k)
		s.releasePort(client, strings.TrimPrefix(k, client+"/"), now.Add(-2*reservationTTL))
	}
}

// reservedPortsLocked drops the expired reservations and returns the port -> key map of the rest; a port reserved
// by more than one key maps to "", which is no key. Allocation uses it to test each candidate port in O(1).
func (s *Server) reservedPortsLocked(now time.Time) map[int]string {
	byPort := make(map[int]string, len(s.reserved))
	for k, r := range s.reserved {
		if now.Sub(r.at) >= reservationTTL {
			delete(s.reserved, k)
			continue
		}
		if _, dup := byPort[r.port]; dup {
			byPort[r.port] = ""
		} else {
			byPort[r.port] = k
		}
	}
	return byPort
}

// handleRegister processes a register request (protocol.md §3.2). Authorization is re-evaluated from the store.
func (c *session) handleRegister(m *proto.Register) {
	srv := c.srv
	tok, perr, err := srv.recheck(c.ctx, c.tokenID)
	if c.ctx.Err() != nil {
		return
	}
	if err != nil {
		c.log.Error("token lookup failed during register", "err", err)
		c.sendError(m.ReqID, proto.CodeInternal, "internal error")
		return
	}
	if perr != nil {
		perr.ReqID = m.ReqID
		perr.Fatal = true
		c.kill("token no longer usable: "+perr.Code, perr)
		return
	}

	var scope string
	switch m.Kind {
	case proto.KindHTTP:
		scope = auth.ScopeTunnelHTTP
	case proto.KindTCP:
		scope = auth.ScopeTunnelTCP
	case proto.KindSSH:
		if !srv.cfg.SSHGateway.Enabled() {
			c.sendError(m.ReqID, proto.CodeInvalidRequest, "the SSH gateway is not enabled on this server (ssh_gateway.listen is empty)")
			return
		}
		scope = auth.ScopeTunnelTCP
	case proto.KindUDP:
		c.sendError(m.ReqID, proto.CodeInvalidRequest, "udp tunnels are not supported yet")
		return
	default:
		c.sendError(m.ReqID, proto.CodeInvalidRequest, "unknown tunnel kind")
		return
	}
	if !tok.HasScope(scope) {
		c.sendError(m.ReqID, proto.CodeForbidden, "token lacks scope "+scope)
		return
	}
	if m.Private && m.Kind != proto.KindSSH {
		c.sendError(m.ReqID, proto.CodeInvalidRequest, "private applies to ssh tunnels only")
		return
	}

	if m.Inspect && m.Kind != proto.KindHTTP {
		c.sendError(m.ReqID, proto.CodeInvalidRequest, "inspect applies to http tunnels only")
		return
	}
	if m.Inspect && !srv.cfg.Traffic.AllowInspect {
		c.sendError(m.ReqID, proto.CodeForbidden, "this server does not allow request inspection (traffic.allow_inspect is false)")
		return
	}

	name := m.Name
	switch {
	case name == "" && m.Kind == proto.KindSSH:
		name = defaultSSHTunnelName
	case name == "":
		name = m.Kind + "-" + randHex(2)
	case !auth.ValidName(name):
		c.sendError(m.ReqID, proto.CodeInvalidRequest, "invalid tunnel name")
		return
	}
	if m.RemotePort != 0 && m.Kind != proto.KindTCP {
		c.sendError(m.ReqID, proto.CodeInvalidRequest, "remote_port applies to tcp tunnels only")
		return
	}
	limit := tok.MaxTunnels
	if limit <= 0 {
		limit = srv.cfg.MaxTunnelsPerClient
	}

	t, perr := srv.createTunnel(c, m, name, limit)
	if perr != nil {
		c.sendError(m.ReqID, perr.Code, perr.Message)
		return
	}
	c.log.Info("tunnel registered", "tunnel", t.id, "kind", t.kind, "name", t.name, "label", t.label, "port", t.port)
	reply := &proto.Registered{ReqID: m.ReqID, TunnelID: t.id, Kind: t.kind, Name: t.name, PublicURL: srv.publicURL(t), Inspect: t.inspect}
	if t.kind == proto.KindSSH {
		reply.Private = t.private
		reply.SSHJump = net.JoinHostPort(srv.cfg.Domain, strconv.Itoa(srv.cfg.SSHGateway.Port()))
	}
	if err := c.send(reply); err != nil {
		c.kill("control write failed: "+err.Error(), nil)
	}
}

// publicURL is the address visitors use for t.
func (s *Server) publicURL(t *tunnel) string {
	if t.kind == proto.KindSSH {
		return "" // reachable only through the SSH gateway, see Registered.SSHJump
	}
	if t.kind == proto.KindTCP {
		return "tcp://" + net.JoinHostPort(s.cfg.Domain, strconv.Itoa(t.port))
	}
	host := t.label + "." + s.cfg.Domain
	if s.cfg.PublicPort > 0 {
		host = net.JoinHostPort(host, strconv.Itoa(s.cfg.PublicPort))
	}
	return s.cfg.PublicScheme + "://" + host
}

// createTunnel claims the tunnel's labels for good, then validates uniqueness and limits and registers the tunnel.
func (s *Server) createTunnel(c *session, m *proto.Register, name string, limit int) (*tunnel, *proto.Error) {
	t := &tunnel{
		id:      randHex(8),
		kind:    m.Kind,
		name:    name,
		nameKey: m.Kind + ":" + name,
		sess:    c,
		private: m.Private,
		inspect: m.Inspect,
	}
	if m.Kind == proto.KindHTTP {
		t.label = name + "-" + c.name
		if !validLabel(t.label) {
			return nil, &proto.Error{Code: proto.CodeInvalidRequest, Message: "tunnel name too long: the hostname label would exceed 63 characters"}
		}
	}

	// The permanent claim comes first and is taken outside the registry lock: it is a store write.
	claimed, perr := s.claimLabels(c.ctx, c, name, claimedLabels(c.name, m.Kind, name, t.label))
	if perr != nil {
		return nil, perr
	}
	t, perr = s.addTunnel(c, m, t, limit)
	if perr != nil {
		s.unclaimLabels(c.name, name, claimed)
		return nil, perr
	}
	return t, nil
}

// addTunnel checks uniqueness and limits and, under the registry lock, allocates and starts t.
func (s *Server) addTunnel(c *session, m *proto.Register, t *tunnel, limit int) (*tunnel, *proto.Error) {
	name := t.name
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || c.dead {
		return nil, &proto.Error{Code: proto.CodeShuttingDown, Message: "session is closing"}
	}
	if _, dup := c.names[t.nameKey]; dup {
		return nil, &proto.Error{Code: proto.CodeNameTaken, Message: "this session already has a tunnel with that name"}
	}
	if len(c.tunnels) >= limit {
		return nil, &proto.Error{Code: proto.CodeLimitExceeded, Message: fmt.Sprintf("tunnel limit reached (%d)", limit)}
	}

	t.ctx, t.cancel = context.WithCancel(c.ctx)
	switch m.Kind {
	case proto.KindHTTP:
		if _, taken := s.labels[t.label]; taken {
			t.cancel()
			return nil, &proto.Error{Code: proto.CodeNameTaken, Message: "hostname is already in use"}
		}
		if s.heldByOtherLocked(addrKey(proto.KindHTTP, t.label), reservationKey(c.name, name), s.now()) {
			t.cancel()
			return nil, &proto.Error{Code: proto.CodeNameTaken, Message: "hostname is already in use"}
		}
		s.initHTTPTunnel(t)
		if s.httpMaxReqs > 0 {
			t.httpSem = make(chan struct{}, s.httpMaxReqs)
		}
		s.labels[t.label] = t
		delete(s.offline, t.label)
		delete(s.held, addrKey(proto.KindHTTP, t.label))
	case proto.KindTCP:
		ln, perr := s.listenTCPLocked(reservationKey(c.name, name), m.RemotePort)
		if perr != nil {
			t.cancel()
			return nil, perr
		}
		t.ln = ln
		t.port = listenerPort(ln)
		t.sem = make(chan struct{}, maxTCPConnsPerTunnel)
		s.ports[t.port] = t
		delete(s.reserved, reservationKey(c.name, name))
		s.holdPort(c.name, name, t.port)
		c.wg.Go(t.acceptLoop)
	case proto.KindSSH:
		if s.conflictingSSHLocked(c.name, name, s.now()) {
			t.cancel()
			return nil, &proto.Error{Code: proto.CodeNameTaken, Message: "this ssh address is already in use"}
		}
		s.sshLabels[sshLabel(c.name, name)] = t
		for _, a := range sshAddrs(c.name, name) {
			delete(s.held, addrKey(proto.KindSSH, a))
		}
		// No public listener: the SSH gateway looks the tunnel up with lookupSSH and opens streams itself.
		n := s.cfg.SSHGateway.MaxConnsPerTunnel
		if n <= 0 {
			n = config.DefaultSSHMaxConnsPerTunnel
		}
		t.sem = make(chan struct{}, n)
	}
	c.tunnels[t.id] = t
	c.names[t.nameKey] = t
	return t, nil
}

func (s *Server) bindTCP(port int) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", net.JoinHostPort(s.cfg.TCPBindHost, strconv.Itoa(port)))
}

// portFreeLocked reports whether port is neither used by a live tunnel nor reserved for another tunnel.
func (s *Server) portFreeLocked(port int, key string, now time.Time) bool {
	if s.ports[port] != nil {
		return false
	}
	for k, r := range s.reserved {
		if now.Sub(r.at) >= reservationTTL {
			delete(s.reserved, k)
			continue
		}
		if r.port == port && k != key {
			return false
		}
	}
	return true
}

// listenTCPLocked binds a public port for the tunnel identified by key: the requested one if given, else its
// reserved one, else a random free port from the configured range.
func (s *Server) listenTCPLocked(key string, requested int) (net.Listener, *proto.Error) {
	now := s.now()
	if requested != 0 {
		if requested < s.portLo || requested > s.portHi {
			return nil, &proto.Error{Code: proto.CodePortUnavailable, Message: "requested port is outside the allowed range"}
		}
		if !s.portFreeLocked(requested, key, now) {
			return nil, &proto.Error{Code: proto.CodePortUnavailable, Message: "requested port is not available"}
		}
		ln, err := s.bindTCP(requested)
		if err != nil {
			return nil, &proto.Error{Code: proto.CodePortUnavailable, Message: "requested port is not available"}
		}
		return ln, nil
	}

	if r, ok := s.reserved[key]; ok && now.Sub(r.at) < reservationTTL && s.ports[r.port] == nil {
		if ln, err := s.bindTCP(r.port); err == nil {
			return ln, nil
		}
	}

	size := s.portHi - s.portLo + 1
	byPort := s.reservedPortsLocked(now)
	try := func(p int) net.Listener {
		if s.ports[p] != nil {
			return nil
		}
		if k, held := byPort[p]; held && k != key {
			return nil
		}
		ln, err := s.bindTCP(p)
		if err != nil {
			return nil
		}
		return ln
	}
	for range min(size, 32) {
		if ln := try(s.portLo + rand.IntN(size)); ln != nil { //nolint:gosec // port choice is not security sensitive
			return ln, nil
		}
	}
	start := rand.IntN(size) //nolint:gosec // see above
	for i := range min(size, 1024) {
		if ln := try(s.portLo + (start+i)%size); ln != nil {
			return ln, nil
		}
	}
	return nil, &proto.Error{Code: proto.CodePortUnavailable, Message: "no free port in the configured range"}
}

func (c *session) handleUnregister(m *proto.Unregister) {
	s := c.srv
	s.mu.Lock()
	t := c.tunnels[m.TunnelID]
	if t != nil {
		s.removeLocked(t, false)
	}
	s.mu.Unlock()
	if t == nil {
		c.log.Debug("unregister of an unknown tunnel", "tunnel", m.TunnelID)
		return
	}
	s.releaseTransport(t)
	c.log.Info("tunnel unregistered", "tunnel", t.id, "name", t.name)
}

// enforceScopes closes tunnels whose scope the (re-read) token no longer grants and tells the client.
func (c *session) enforceScopes(tok *store.Token) {
	s := c.srv
	var closed []*tunnel
	s.mu.Lock()
	for _, t := range c.tunnels {
		scope := auth.ScopeTunnelHTTP
		if t.kind == proto.KindTCP || t.kind == proto.KindSSH {
			scope = auth.ScopeTunnelTCP
		}
		if !tok.HasScope(scope) {
			s.removeLocked(t, false)
			closed = append(closed, t)
		}
	}
	s.mu.Unlock()
	s.releaseTransport(closed...)
	for _, t := range closed {
		c.log.Info("tunnel closed: scope revoked", "tunnel", t.id, "name", t.name)
		if err := c.send(&proto.TunnelClosed{TunnelID: t.id, Reason: "token no longer grants this tunnel kind"}); err != nil {
			c.kill("control write failed: "+err.Error(), nil)
			return
		}
	}
}

// listenerPort returns the TCP port ln is bound to.
func listenerPort(ln net.Listener) int {
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}
