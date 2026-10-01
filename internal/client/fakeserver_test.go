// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/binary"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/transport"
)

// fakeServer is a minimal protocol-speaking server for client tests. It does not use internal/server.
type fakeServer struct {
	t      *testing.T
	ts     *httptest.Server
	hbMS   int           // heartbeat_interval_ms in hello_ok
	pingIn time.Duration // if > 0 the default handler pings this often
	// expectRegs is how many register messages the default handler answers before it reports the connection on
	// ready.
	expectRegs int
	// handler runs once per connection in its own goroutine. Nil means defaultHandler.
	handler func(*srvConn)
	// regError, if set, may refuse a registration of the n-th connection (1-based).
	regError func(n int, reg *proto.Register) *proto.Error
	// regGate, if set, makes the default handler wait for one token per register message before it answers.
	regGate chan struct{}
	// ignorePrivate makes the default handler behave like a server that does not know the "private" field.
	ignorePrivate bool

	mu     sync.Mutex
	conns  []*srvConn
	wg     sync.WaitGroup
	ready  chan *srvConn // connections whose registrations were answered
	accept chan *srvConn // every connection, as soon as the WebSocket is up
}

type srvConn struct {
	fs    *fakeServer
	n     int // 1-based
	at    time.Time
	sess  transport.Session
	ctl   net.Conn
	hello *proto.Hello

	wmu     sync.Mutex
	mu      sync.Mutex
	regs    []*proto.Register
	tunnels map[string]string // tunnel name -> id
	pongs   chan uint64
	regCh   chan *proto.Register // every register message, as soon as it is read
	unregCh chan string          // tunnel id of every unregister message
	unregs  []string
	live    map[string]string // tunnel name -> id of tunnels registered and not unregistered
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{
		t:          t,
		hbMS:       15000,
		expectRegs: 1,
		ready:      make(chan *srvConn, 16),
		accept:     make(chan *srvConn, 16),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(proto.ConnectPath, func(w http.ResponseWriter, r *http.Request) {
		sess, err := transport.AcceptWebSocket(w, r, &net.TCPAddr{})
		if err != nil {
			t.Errorf("fake server accept: %v", err)
			return
		}
		fs.mu.Lock()
		c := &srvConn{
			fs: fs, n: len(fs.conns) + 1, at: time.Now(), sess: sess,
			tunnels: map[string]string{}, pongs: make(chan uint64, 256),
			regCh: make(chan *proto.Register, 256), unregCh: make(chan string, 256), live: map[string]string{},
		}
		fs.conns = append(fs.conns, c)
		fs.mu.Unlock()
		fs.accept <- c
		fs.wg.Go(func() {
			if fs.handler != nil {
				fs.handler(c)
			} else {
				fs.defaultHandler(c)
			}
		})
	})
	fs.ts = httptest.NewServer(mux)
	t.Cleanup(func() {
		fs.mu.Lock()
		conns := append([]*srvConn(nil), fs.conns...)
		fs.mu.Unlock()
		for _, c := range conns {
			_ = c.sess.Close()
		}
		fs.wg.Wait()
		fs.ts.Close()
	})
	return fs
}

func (fs *fakeServer) url() string { return fs.ts.URL }

func (fs *fakeServer) connCount() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return len(fs.conns)
}

func (fs *fakeServer) conn(n int) *srvConn {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.conns[n-1]
}

func (c *srvConn) send(m proto.Message) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return proto.WriteMessage(c.ctl, m)
}

// handshake accepts the control stream and reads hello. It does not reply.
func (c *srvConn) handshake() bool {
	ctl, err := c.sess.Accept()
	if err != nil {
		return false
	}
	c.ctl = ctl
	_ = ctl.SetReadDeadline(time.Now().Add(5 * time.Second))
	h, err := proto.ReadAs[*proto.Hello](ctl)
	if err != nil {
		return false
	}
	_ = ctl.SetReadDeadline(time.Time{})
	c.hello = h
	return true
}

func (c *srvConn) replyOK() error {
	return c.send(&proto.HelloOK{
		SessionID:           "sess-" + strconv.Itoa(c.n),
		ClientName:          "home",
		ServerVersion:       "fake",
		HeartbeatIntervalMS: c.fs.hbMS,
	})
}

func (c *srvConn) tunnelID(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tunnels[name]
}

func (c *srvConn) registrations() []*proto.Register {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*proto.Register(nil), c.regs...)
}

func (fs *fakeServer) defaultHandler(c *srvConn) {
	if !c.handshake() || c.replyOK() != nil {
		return
	}
	if fs.pingIn > 0 {
		fs.wg.Go(func() {
			tk := time.NewTicker(fs.pingIn)
			defer tk.Stop()
			for seq := uint64(1); ; seq++ {
				select {
				case <-c.sess.Done():
					return
				case <-tk.C:
					if c.send(&proto.Ping{Seq: seq}) != nil {
						return
					}
				}
			}
		})
	}
	answered := 0
	for {
		m, err := proto.ReadMessage(c.ctl)
		if err != nil {
			if errors.Is(err, proto.ErrUnknownType) {
				continue
			}
			return
		}
		switch m := m.(type) {
		case *proto.Unregister:
			c.mu.Lock()
			c.unregs = append(c.unregs, m.TunnelID)
			for name, id := range c.live {
				if id == m.TunnelID {
					delete(c.live, name)
				}
			}
			c.mu.Unlock()
			select {
			case c.unregCh <- m.TunnelID:
			default:
			}
		case *proto.Register:
			select {
			case c.regCh <- m:
			default:
			}
			if fs.regGate != nil {
				select {
				case <-fs.regGate:
				case <-c.sess.Done():
					return
				}
			}
			if fs.regError != nil {
				if e := fs.regError(c.n, m); e != nil {
					e.ReqID = m.ReqID
					_ = c.send(e)
					answered++
					break
				}
			}
			c.mu.Lock()
			if _, taken := c.live[m.Name]; taken {
				c.mu.Unlock()
				_ = c.send(&proto.Error{ReqID: m.ReqID, Code: proto.CodeNameTaken, Message: "name " + m.Name + " is taken"})
				answered++
				break
			}
			c.regs = append(c.regs, m)
			id := "t" + strconv.Itoa(c.n) + "-" + strconv.Itoa(len(c.regs))
			name := m.Name
			if name == "" {
				name = "auto-" + strconv.Itoa(len(c.regs))
			}
			c.tunnels[name] = id
			c.live[name] = id
			c.mu.Unlock()
			url := "https://" + name + "-home.tun.test"
			if m.Kind == proto.KindTCP {
				port := m.RemotePort
				if port == 0 {
					port = 20000 + len(c.regs)
				}
				url = "tcp://tun.test:" + strconv.Itoa(port)
			}
			reply := &proto.Registered{ReqID: m.ReqID, TunnelID: id, Kind: m.Kind, Name: name, PublicURL: url}
			if m.Kind == proto.KindSSH {
				reply.PublicURL = ""
				reply.SSHJump = "tun.test:2222"
				reply.Private = m.Private && !fs.ignorePrivate
			}
			_ = c.send(reply)
			answered++
		case *proto.Pong:
			select {
			case c.pongs <- m.Seq:
			default:
			}
		}
		if answered == fs.expectRegs {
			answered++ // report once
			fs.ready <- c
		}
	}
}

// rejectHandler answers hello with an error and closes the session.
func rejectHandler(e *proto.Error) func(*srvConn) {
	return func(c *srvConn) {
		if !c.handshake() {
			return
		}
		_ = c.send(e)
		// give the client a moment to read the frame before the connection goes away
		time.Sleep(20 * time.Millisecond)
		_ = c.sess.Close()
	}
}

// rawFrame writes a frame with an arbitrary JSON payload to the control stream.
func (c *srvConn) rawFrame(payload string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	copy(buf[4:], payload)
	_, err := c.ctl.Write(buf)
	return err
}

// openStream opens a data stream for the named tunnel and writes the stream header.
func (c *srvConn) openStream(t *testing.T, tunnelName string) net.Conn {
	t.Helper()
	st, err := c.sess.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	err = proto.WriteMessage(st, &proto.StreamHeader{TunnelID: c.tunnelID(tunnelName), RemoteAddr: "203.0.113.7:4242"})
	if err != nil {
		t.Fatalf("write stream header: %v", err)
	}
	return st
}

func newToken(t *testing.T) string {
	t.Helper()
	tok, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return tok.String()
}

func (c *srvConn) unregistrations() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.unregs...)
}

// liveTunnels returns the names of the tunnels that are registered and not unregistered, sorted.
func (c *srvConn) liveTunnels() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Sorted(maps.Keys(c.live))
}
