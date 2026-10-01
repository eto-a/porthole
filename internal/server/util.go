// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/hashicorp/yamux"

	"github.com/eto-a/porthole/internal/transport"
)

// hostAddr is a net.Addr built from an already formatted "host:port" string.
type hostAddr string

func (hostAddr) Network() string  { return "tcp" }
func (a hostAddr) String() string { return string(a) }

// randHex returns 2n random hex characters.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails since Go 1.24
	return hex.EncodeToString(b)
}

// normalizeHost strips the port and a trailing dot from an HTTP Host and lowercases it.
func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// validLabel reports whether s is a valid single DNS label: 1-63 chars of [a-z0-9-], no hyphen at either end.
func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// visitorAddr returns the visitor's address as "ip:port". Without trust_proxy_headers it is r.RemoteAddr. With it,
// the address comes from X-Forwarded-For (port 0, the proxy does not tell us the port), taken from the right as
// proxies append to what they received:
//   - with trusted_proxies configured, X-Forwarded-For is honoured only when the direct peer is in that list, and the
//     result is the right-most address that is not itself a trusted proxy (the left side is client-controlled);
//   - without trusted_proxies, the right-most address is used, which is what the single proxy in front of us saw.
//
// In every other case (header absent, unparsable hop, untrusted peer) it falls back to r.RemoteAddr.
func (s *Server) visitorAddr(r *http.Request) string {
	if !s.cfg.TrustProxyHeaders {
		return r.RemoteAddr
	}
	if len(s.trustedNets) > 0 {
		peer, err := netip.ParseAddr(ipOf(r.RemoteAddr))
		if err != nil || !s.isTrustedProxy(peer) {
			return r.RemoteAddr
		}
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return r.RemoteAddr
		}
		if s.isTrustedProxy(a) && i > 0 {
			continue
		}
		return netip.AddrPortFrom(a.Unmap(), 0).String()
	}
	return r.RemoteAddr
}

// isTrustedProxy reports whether a is inside trusted_proxies.
func (s *Server) isTrustedProxy(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.trustedNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseTrustedProxies converts trusted_proxies entries (addresses or CIDR ranges; validated by config) to prefixes.
func parseTrustedProxies(entries []string) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// ipOf extracts the IP part of an "ip:port" string; it returns addr unchanged when it has no port.
func ipOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// isTransportError reports whether err means the connection itself failed or closed (the peer went away, a
// deadline passed), as opposed to the peer having sent something invalid.
func isTransportError(err error) bool {
	var ne net.Error
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, transport.ErrPreAuthBudget) ||
		errors.Is(err, yamux.ErrSessionShutdown) || errors.Is(err, yamux.ErrStreamClosed) ||
		errors.Is(err, yamux.ErrConnectionReset) || errors.Is(err, yamux.ErrConnectionWriteTimeout) ||
		errors.As(err, &ne)
}

// warnSharedAddresses logs a warning when the listener looks like it sits behind a reverse proxy (loopback or
// private bind address) while neither trust_proxy_headers nor proxy_protocol is set: every per-IP limit and
// failure bucket then sees the proxy's address, so one abusive visitor can lock out all the others.
func (s *Server) warnSharedAddresses() {
	if s.cfg.TrustProxyHeaders || s.cfg.ProxyProtocol {
		return
	}
	host, _, err := net.SplitHostPort(s.cfg.Listen)
	if err != nil {
		return
	}
	if a, err := netip.ParseAddr(host); err == nil && (a.IsLoopback() || a.IsPrivate()) {
		s.log.Warn("listening on a loopback or private address without trust_proxy_headers or proxy_protocol: "+
			"if a reverse proxy sits in front, all visitors share its address in per-IP limits",
			"listen", s.cfg.Listen)
	}
}
