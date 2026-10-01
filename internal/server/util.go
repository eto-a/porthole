// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"
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

// visitorAddr returns the visitor's address as "ip:port". With trustProxy set it takes the first address of
// X-Forwarded-For (port 0, the proxy does not tell us the port), falling back to r.RemoteAddr.
func visitorAddr(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
				return netip.AddrPortFrom(a.Unmap(), 0).String()
			}
		}
	}
	return r.RemoteAddr
}

// ipOf extracts the IP part of an "ip:port" string; it returns addr unchanged when it has no port.
func ipOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
