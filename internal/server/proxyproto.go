// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// proxyHeaderTimeout bounds how long a connection may take to deliver its PROXY header (the proxy sends it right
// after connecting, so a slow one is broken or hostile).
const proxyHeaderTimeout = 5 * time.Second

// wrapProxyProtocol makes ln understand PROXY protocol v1/v2 (HAProxy spec) from cfg.TrustedProxies, so that
// RemoteAddr of an accepted connection is the visitor address the proxy reports. It must wrap the raw TCP
// listener, before TLS. Policy, as in Caddy's proxy_protocol listener wrapper (allow list) but stricter for
// trusted peers:
//   - a peer in trusted_proxies must send a header, otherwise its first read fails with an error;
//   - any other peer must not send one (a visitor cannot spoof its address): such a connection fails on first
//     read, while a headerless connection from it is served as a plain one with its real address.
//
// The header is parsed lazily on the first Read or RemoteAddr call, which happens in the per-connection
// goroutine of http.Server and of the SSH gateway, never in the accept loop.
func wrapProxyProtocol(ln net.Listener, trusted []string) (net.Listener, error) {
	policy, err := proxyproto.PolicyFromRanges(trusted, proxyproto.REQUIRE, proxyproto.REJECT)
	if err != nil {
		return nil, fmt.Errorf("server: trusted_proxies: %w", err)
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ConnPolicy:        policy,
		ReadHeaderTimeout: proxyHeaderTimeout,
	}, nil
}

// wrapProxyIf wraps ln when on is set and returns it unchanged otherwise. On error it closes ln.
func (s *Server) wrapProxyIf(ln net.Listener, on bool) (net.Listener, error) {
	if !on {
		return ln, nil
	}
	w, err := wrapProxyProtocol(ln, s.cfg.TrustedProxies)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	return w, nil
}

// peerAddr returns the remote address of conn without waiting for a PROXY header: for a PROXY-wrapped connection
// it is the address of the proxy. Use it only where blocking the caller is not acceptable (an accept loop).
func peerAddr(conn net.Conn) net.Addr {
	if pc, ok := conn.(*proxyproto.Conn); ok {
		return pc.Raw().RemoteAddr()
	}
	return conn.RemoteAddr()
}
