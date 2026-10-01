// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package transport provides the multiplexed session between a porthole client and server.
//
// v0.1 implements WebSocket + yamux (see docs/adr/0001-transport-and-framing.md). QUIC will implement the same
// Session interface in v0.2.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/eto-a/porthole/internal/proto"
)

// Session is a multiplexed connection between client and server.
// Streams are full-duplex net.Conns; closing the Session closes all of its streams.
type Session interface {
	// Open opens a new stream to the peer.
	Open() (net.Conn, error)
	// Accept waits for the next stream opened by the peer. It returns an error once the session is closed.
	Accept() (net.Conn, error)
	// Close closes the session and every stream on it.
	Close() error
	// Done is closed when the session is closed for any reason.
	Done() <-chan struct{}
	// RemoteAddr is the peer address as seen by this side.
	RemoteAddr() net.Addr
}

// ErrBadSubprotocol is returned when the peer did not negotiate the porthole WebSocket subprotocol.
var ErrBadSubprotocol = errors.New("transport: peer did not negotiate " + proto.WSSubprotocol)

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.AcceptBacklog = 256
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 20 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	c.StreamOpenTimeout = 30 * time.Second
	c.StreamCloseTimeout = 2 * time.Minute
	c.LogOutput = io.Discard // errors are surfaced through return values
	return c
}

type yamuxSession struct {
	s      *yamux.Session
	cancel context.CancelFunc // ends the WebSocket's lifetime context
	remote net.Addr
}

func (y *yamuxSession) Open() (net.Conn, error)   { return y.s.OpenStream() }
func (y *yamuxSession) Accept() (net.Conn, error) { return y.s.AcceptStream() }
func (y *yamuxSession) Done() <-chan struct{}     { return y.s.CloseChan() }
func (y *yamuxSession) RemoteAddr() net.Addr      { return y.remote }

func (y *yamuxSession) Close() error {
	err := y.s.Close()
	y.cancel()
	return err
}

// watch releases the WebSocket context when yamux closes on its own (keepalive failure, peer close).
func (y *yamuxSession) watch() {
	<-y.s.CloseChan()
	y.cancel()
}

// AcceptWebSocket upgrades an HTTP request to a server-side Session.
// remote is the visitor address to report (the caller decides whether to trust proxy headers).
func AcceptWebSocket(w http.ResponseWriter, r *http.Request, remote net.Addr) (Session, error) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{proto.WSSubprotocol},
		CompressionMode: websocket.CompressionDisabled, // tunnelled data is often already compressed or encrypted
	})
	if err != nil {
		return nil, fmt.Errorf("transport: websocket accept: %w", err)
	}
	if c.Subprotocol() != proto.WSSubprotocol {
		_ = c.Close(websocket.StatusPolicyViolation, "unsupported subprotocol")
		return nil, ErrBadSubprotocol
	}
	ctx, cancel := context.WithCancel(context.Background())
	nc := websocket.NetConn(ctx, c, websocket.MessageBinary)
	s, err := yamux.Server(nc, yamuxConfig())
	if err != nil {
		cancel()
		_ = nc.Close()
		return nil, fmt.Errorf("transport: yamux server: %w", err)
	}
	ys := &yamuxSession{s: s, cancel: cancel, remote: remote}
	go ys.watch()
	return ys, nil
}

// DialOptions configures DialWebSocket.
type DialOptions struct {
	// TLSConfig is used for wss:// URLs. Nil means the system defaults.
	TLSConfig *tls.Config
	// Header is sent with the upgrade request.
	Header http.Header
}

// DialWebSocket connects to a porthole server and returns a client-side Session.
// url is the full endpoint, e.g. wss://tun.example.com/_porthole/v1/connect.
// HTTP(S)_PROXY environment variables are honoured.
// ctx bounds only the dial; the returned Session lives until closed.
func DialWebSocket(ctx context.Context, url string, opts DialOptions) (Session, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	if opts.TLSConfig != nil {
		tr.TLSClientConfig = opts.TLSConfig
	}
	c, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		// The token travels in the hello message on the resulting connection, so a redirect (to another host, or from
		// https to http) must not be followed.
		HTTPClient: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		HTTPHeader:      opts.Header,
		Subprotocols:    []string{proto.WSSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("transport: websocket dial %s: %w", url, err)
	}
	if c.Subprotocol() != proto.WSSubprotocol {
		_ = c.Close(websocket.StatusPolicyViolation, "unsupported subprotocol")
		return nil, ErrBadSubprotocol
	}
	lifeCtx, cancel := context.WithCancel(context.Background())
	nc := websocket.NetConn(lifeCtx, c, websocket.MessageBinary)
	s, err := yamux.Client(nc, yamuxConfig())
	if err != nil {
		cancel()
		_ = nc.Close()
		return nil, fmt.Errorf("transport: yamux client: %w", err)
	}
	ys := &yamuxSession{s: s, cancel: cancel, remote: nc.RemoteAddr()}
	go ys.watch()
	return ys, nil
}
