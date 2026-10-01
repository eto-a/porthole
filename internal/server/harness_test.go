// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/transport"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

const testDomain = "example.test"

// ---- fake store -----------------------------------------------------------------------------------------------

type fakeStore struct {
	mu      sync.Mutex
	tokens  map[string]*store.Token
	touched map[string]time.Time
	failGet atomic.Bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{tokens: map[string]*store.Token{}, touched: map[string]time.Time{}}
}

func clone(t *store.Token) *store.Token {
	c := *t
	c.Scopes = append([]string(nil), t.Scopes...)
	return &c
}

func (f *fakeStore) CreateToken(_ context.Context, t *store.Token) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[t.ID] = clone(t)
	return nil
}

func (f *fakeStore) GetToken(_ context.Context, id string) (*store.Token, error) {
	if f.failGet.Load() {
		return nil, errors.New("fake store failure")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return clone(t), nil
}

func (f *fakeStore) ListTokens(context.Context) ([]*store.Token, error) { return nil, nil }

func (f *fakeStore) RevokeToken(_ context.Context, idOrName string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.ID == idOrName || t.Name == idOrName {
			t.RevokedAt = &at
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeStore) TouchToken(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched[id] = at
	return nil
}

func (f *fakeStore) Close() error { return nil }

// update mutates a stored token in place.
func (f *fakeStore) update(id string, fn func(*store.Token)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.tokens[id])
}

func (f *fakeStore) wasTouched(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.touched[id]
	return ok
}

// testToken is a token created in the fake store.
type testToken struct {
	id, str string
}

func (f *fakeStore) newToken(t *testing.T, name string, mut ...func(*store.Token)) testToken {
	t.Helper()
	g, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tok := &store.Token{
		ID:         g.ID,
		Name:       name,
		SecretHash: g.Hash(),
		Last4:      g.Last4(),
		Scopes:     append([]string(nil), auth.DefaultScopes...),
		CreatedAt:  time.Now(),
	}
	for _, m := range mut {
		m(tok)
	}
	_ = f.CreateToken(context.Background(), tok)
	return testToken{id: g.ID, str: g.String()}
}

// ---- fake clock -----------------------------------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---- harness --------------------------------------------------------------------------------------------------

type harness struct {
	t     *testing.T
	st    *fakeStore
	cfg   *config.Config
	clock *fakeClock
	srv   *Server
	web   *httptest.Server
	wsURL string
	httpc *http.Client
	lo    int
	hi    int
}

// freePortRange returns a small port range whose first port was free a moment ago.
func freePortRange(t *testing.T) (lo, hi int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	lo = min(p, 65535-19)
	return lo, lo + 19
}

func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// newHarness starts a Server behind httptest. mods may adjust the config and the options.
func newHarness(t *testing.T, mods ...func(*config.Config, *Options)) *harness {
	t.Helper()
	lo, hi := freePortRange(t)
	cfg := config.Default()
	cfg.Domain = testDomain
	cfg.TCPBindHost = "127.0.0.1"
	cfg.TCPPortRange = itoa(lo) + "-" + itoa(hi)
	cfg.DataDir = "unused"

	h := &harness{t: t, st: newFakeStore(), cfg: cfg, clock: newFakeClock(), lo: lo, hi: hi}
	opts := Options{
		Config:            cfg,
		Store:             h.st,
		Logger:            quietLogger(),
		Version:           "test",
		Now:               h.clock.Now,
		HeartbeatInterval: time.Minute, // quiet unless a test asks for pings
	}
	for _, m := range mods {
		m(cfg, &opts)
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	t.Cleanup(func() { _ = srv.Close() })

	// transport.DialWebSocket cannot override the Host header, so the shim presents the control endpoint as the
	// configured domain. Everything else (vhosts) is reached with explicit Host headers.
	h.web = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == proto.ConnectPath {
			r.Host = cfg.Domain
		}
		srv.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(h.web.Close)
	h.wsURL = "ws" + strings.TrimPrefix(h.web.URL, "http") + proto.ConnectPath
	h.httpc = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return h
}

func itoa(i int) string { return strconv.Itoa(i) }

// httpReply is what is left of a visitor response once its body has been read and closed.
type httpReply struct {
	StatusCode int
	Header     http.Header
}

// get performs a visitor request against the server with an explicit Host header.
func (h *harness) get(host, path string, hdr http.Header) (httpReply, string) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.web.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Host = host
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := h.httpc.Do(req)
	if err != nil {
		h.t.Fatalf("GET %s (Host %s): %v", path, host, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read body: %v", err)
	}
	return httpReply{StatusCode: resp.StatusCode, Header: resp.Header}, string(b)
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (s *Server) sessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Server) tunnelCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.labels) + len(s.ports)
}

// ---- protocol client ------------------------------------------------------------------------------------------

// client emulates a porthole client on the wire.
type client struct {
	t       *testing.T
	ts      transport.Session
	ctrl    net.Conn
	ok      *proto.HelloOK
	msgs    chan proto.Message // every control message except pings
	done    chan struct{}      // closed when the control stream ends
	noPong  atomic.Bool
	pings   atomic.Int64
	wmu     sync.Mutex
	reqID   int
	wg      sync.WaitGroup
	headers chan proto.StreamHeader
}

func dialSession(t *testing.T, wsURL string, opts transport.DialOptions) (transport.Session, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ts, err := transport.DialWebSocket(ctx, wsURL, opts)
	if err != nil {
		t.Fatalf("dial %s: %v", wsURL, err)
	}
	ctrl, err := ts.Open()
	if err != nil {
		_ = ts.Close()
		t.Fatalf("open control stream: %v", err)
	}
	return ts, ctrl
}

// rawHandshake sends hello and returns the server's first reply; the session is closed afterwards.
func rawHandshake(t *testing.T, wsURL string, hello *proto.Hello) proto.Message {
	t.Helper()
	ts, ctrl := dialSession(t, wsURL, transport.DialOptions{})
	defer ts.Close()
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
	if err := proto.WriteMessage(ctrl, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	m, err := proto.ReadMessage(ctrl)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return m
}

func goodHello(token string) *proto.Hello {
	return &proto.Hello{ProtocolVersion: proto.Version, Token: token, ClientVersion: "test", OS: "test/test"}
}

// loginAt connects, authenticates and starts the client's background reader.
func loginAt(t *testing.T, wsURL, token string, opts transport.DialOptions) *client {
	t.Helper()
	ts, ctrl := dialSession(t, wsURL, opts)
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
	if err := proto.WriteMessage(ctrl, goodHello(token)); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	ok, err := proto.ReadAs[*proto.HelloOK](ctrl)
	if err != nil {
		_ = ts.Close()
		t.Fatalf("handshake: %v", err)
	}
	_ = ctrl.SetDeadline(time.Time{})
	c := &client{
		t:       t,
		ts:      ts,
		ctrl:    ctrl,
		ok:      ok,
		msgs:    make(chan proto.Message, 64),
		done:    make(chan struct{}),
		headers: make(chan proto.StreamHeader, 64),
	}
	c.wg.Add(1)
	go c.readLoop()
	t.Cleanup(c.close)
	return c
}

func (h *harness) login(token testToken) *client {
	h.t.Helper()
	return loginAt(h.t, h.wsURL, token.str, transport.DialOptions{})
}

func (c *client) readLoop() {
	defer c.wg.Done()
	defer close(c.done)
	for {
		m, err := proto.ReadMessage(c.ctrl)
		if errors.Is(err, proto.ErrUnknownType) {
			continue
		}
		if err != nil {
			return
		}
		if p, ok := m.(*proto.Ping); ok {
			c.pings.Add(1)
			if !c.noPong.Load() {
				_ = c.write(&proto.Pong{Seq: p.Seq})
			}
			continue
		}
		select {
		case c.msgs <- m:
		default:
			c.t.Errorf("client message buffer full, dropping %s", m.MsgType())
		}
	}
}

func (c *client) write(m proto.Message) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return proto.WriteMessage(c.ctrl, m)
}

func (c *client) close() {
	_ = c.ts.Close()
	c.wg.Wait()
}

// next returns the next non-ping control message.
func (c *client) next() proto.Message {
	c.t.Helper()
	select {
	case m := <-c.msgs:
		return m
	case <-c.done:
		// drain anything that raced with the close
		select {
		case m := <-c.msgs:
			return m
		default:
		}
		c.t.Fatal("control stream closed while waiting for a message")
	case <-time.After(5 * time.Second):
		c.t.Fatal("timed out waiting for a control message")
	}
	return nil
}

// register sends a register request and returns the reply (*proto.Registered or *proto.Error).
func (c *client) register(kind, name string, port int) proto.Message {
	c.t.Helper()
	c.reqID++
	if err := c.write(&proto.Register{ReqID: c.reqID, Kind: kind, Name: name, RemotePort: port}); err != nil {
		c.t.Fatalf("write register: %v", err)
	}
	m := c.next()
	switch r := m.(type) {
	case *proto.Registered:
		if r.ReqID != c.reqID {
			c.t.Fatalf("registered req_id %d, want %d", r.ReqID, c.reqID)
		}
	case *proto.Error:
		if r.ReqID != c.reqID && !r.Fatal {
			c.t.Fatalf("error req_id %d, want %d", r.ReqID, c.reqID)
		}
	}
	return m
}

func (c *client) mustRegister(kind, name string, port int) *proto.Registered {
	c.t.Helper()
	m := c.register(kind, name, port)
	r, ok := m.(*proto.Registered)
	if !ok {
		c.t.Fatalf("register %s %q: got %#v, want registered", kind, name, m)
	}
	return r
}

func (c *client) registerErr(kind, name string, port int) *proto.Error {
	c.t.Helper()
	m := c.register(kind, name, port)
	e, ok := m.(*proto.Error)
	if !ok {
		c.t.Fatalf("register %s %q: got %#v, want error", kind, name, m)
	}
	return e
}

func (c *client) waitClosed() {
	c.t.Helper()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		c.t.Fatal("timed out waiting for the session to close")
	}
}

// expectFatal waits for a fatal error with the given code followed by the end of the session.
func (c *client) expectFatal(code string) *proto.Error {
	c.t.Helper()
	m := c.next()
	e, ok := m.(*proto.Error)
	if !ok {
		c.t.Fatalf("got %#v, want error %s", m, code)
	}
	if e.Code != code || !e.Fatal {
		c.t.Fatalf("got error %+v, want fatal %s", e, code)
	}
	c.waitClosed()
	return e
}

// serve answers data streams opened by the server: it reads the stream header and calls handler.
func (c *client) serve(handler func(proto.StreamHeader, net.Conn)) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			st, err := c.ts.Accept()
			if err != nil {
				return
			}
			c.wg.Add(1)
			go func() {
				defer c.wg.Done()
				_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
				hdr, err := proto.ReadAs[*proto.StreamHeader](st)
				if err != nil {
					_ = st.Close()
					return
				}
				_ = st.SetReadDeadline(time.Time{})
				select {
				case c.headers <- *hdr:
				default:
				}
				handler(*hdr, st)
			}()
		}
	}()
}

// forward returns a stream handler that connects every stream to a local TCP address, like the real client.
func forward(addr string) func(proto.StreamHeader, net.Conn) {
	return func(_ proto.StreamHeader, st net.Conn) {
		bc, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			_ = st.Close()
			return
		}
		pipe(st, bc)
	}
}

// writeRawFrame writes a hand-made control frame.
func writeRawFrame(c *client, payload string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	_, err := c.ctrl.Write(frame)
	return err
}
