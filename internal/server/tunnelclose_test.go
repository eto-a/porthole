// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/traffic"
)

// closeTunnelBackend answers /stream with an endless response and /ws with an upgrade that then stays open.
func closeTunnelBackend(t *testing.T) *httptest.Server {
	t.Helper()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stream":
			w.WriteHeader(http.StatusOK)
			for {
				if _, err := io.WriteString(w, "tick\n"); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
		case "/ws":
			conn, brw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			_ = brw.Flush()
			_, _ = io.Copy(io.Discard, conn)
		}
	}))
	t.Cleanup(b.Close)
	return b
}

func waitDone(t *testing.T, what string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s survived the unregister of its tunnel", what)
	}
}

// A request that is being served when its tunnel is unregistered must end with it, not run on against the client.
func TestUnregisterEndsRunningRequest(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "app", 0)
	c.serve(forward(closeTunnelBackend(t).Listener.Addr().String()))

	req, _ := http.NewRequest(http.MethodGet, h.web.URL+"/stream", nil)
	req.Host = "app-home." + testDomain
	hc := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	done := make(chan struct{})
	body := resp.Body
	go func() { defer close(done); _, _ = io.Copy(io.Discard, body) }()
	time.Sleep(100 * time.Millisecond) // the body is flowing

	if err := c.write(&proto.Unregister{TunnelID: reg.TunnelID}); err != nil {
		t.Fatal(err)
	}
	waitDone(t, "the response body", done)
}

func TestUnregisterEndsWebSocket(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "app", 0)
	c.serve(forward(closeTunnelBackend(t).Listener.Addr().String()))

	conn, err := net.Dial("tcp", h.web.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: app-home."+testDomain+"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	defer resp.Body.Close()
	_ = conn.SetReadDeadline(time.Time{})

	if err := c.write(&proto.Unregister{TunnelID: reg.TunnelID}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(io.Discard, br) }()
	waitDone(t, "the websocket", done)
}

// A tunnel that has been closed opens no new stream to its client, even for a caller that still holds it.
func TestClosedTunnelDoesNotDial(t *testing.T) {
	h := newHarness(t)
	c := h.login(h.st.newToken(t, "home"))
	reg := c.mustRegister(proto.KindHTTP, "app", 0)
	c.serve(forward(closeTunnelBackend(t).Listener.Addr().String()))

	h.srv.mu.Lock()
	tun := h.srv.labels["app-home"]
	h.srv.mu.Unlock()
	if tun == nil {
		t.Fatal("no tunnel")
	}
	if err := c.write(&proto.Unregister{TunnelID: reg.TunnelID}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unregister", func() bool { return h.srv.tunnelCount() == 0 })

	req, _ := http.NewRequest(http.MethodGet, "http://app-home/stream", nil)
	if resp, err := tun.tr.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a closed tunnel served a request")
	}
	select {
	case hdr := <-c.headers:
		t.Fatalf("a closed tunnel opened a stream: %+v", hdr)
	case <-time.After(200 * time.Millisecond):
	}
}

// A replay goes through the same per-tunnel request limit as a visitor: it must not run a request beyond it.
func TestReplayHonoursRequestLimit(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config, _ *Options) { cfg.Limits.MaxHTTPRequestsPerTunnel = 1 })
	c := h.login(h.st.newToken(t, "home"))
	if _, ok := c.registerInspect(proto.KindHTTP, "web").(*proto.Registered); !ok {
		t.Fatal("register inspect")
	}
	c.serve(forward(closeTunnelBackend(t).Listener.Addr().String()))

	// Anything but /stream and /ws answers with an empty 200.
	h.visit("web-home."+testDomain, http.MethodGet, "/plain", "", nil)
	orig := waitRequests(t, h.srv, traffic.RequestFilter{}, 1)[0]
	if _, err := h.srv.ReplayRequest(context.Background(), orig.ID); err != nil {
		t.Fatalf("replay on an idle tunnel: %v", err)
	}

	// A visitor holds the only slot.
	req, _ := http.NewRequest(http.MethodGet, h.web.URL+"/stream", nil)
	req.Host = "web-home." + testDomain
	hc := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if _, err := h.srv.ReplayRequest(context.Background(), orig.ID); !errors.Is(err, ErrReplayRefused) || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("replay at the request limit: %v, want a refusal saying the tunnel is busy", err)
	}
}
