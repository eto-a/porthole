// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

func withGateway(cfg *config.Config, _ *Options) { cfg.SSHGateway.Listen = ":2222" }

// registerSSH sends a register request of kind ssh with the private flag and returns the reply.
func (c *client) registerSSH(name string, private bool) proto.Message {
	c.t.Helper()
	c.reqID++
	if err := c.write(&proto.Register{ReqID: c.reqID, Kind: proto.KindSSH, Name: name, Private: private}); err != nil {
		c.t.Fatalf("write register: %v", err)
	}
	return c.next()
}

func TestSSHRegisterNeedsGateway(t *testing.T) {
	h := newHarness(t) // ssh_gateway.listen is empty: the gateway is off
	c := h.login(h.st.newToken(t, "home"))
	e := c.registerErr(proto.KindSSH, "", 0)
	if e.Code != proto.CodeInvalidRequest || !strings.Contains(e.Message, "SSH gateway") {
		t.Fatalf("got %+v, want invalid_request mentioning the SSH gateway", e)
	}
}

func TestSSHRegister(t *testing.T) {
	h := newHarness(t, withGateway)
	c := h.login(h.st.newToken(t, "home"))

	reg, ok := c.registerSSH("", false).(*proto.Registered)
	if !ok {
		t.Fatal("register ssh failed")
	}
	if reg.Kind != proto.KindSSH || reg.Name != "ssh" || reg.Private || reg.PublicURL != "" {
		t.Errorf("registered %+v", reg)
	}
	if reg.SSHJump != testDomain+":2222" {
		t.Errorf("ssh_jump %q", reg.SSHJump)
	}
	h.srv.mu.Lock()
	ports, labels := len(h.srv.ports), len(h.srv.labels)
	h.srv.mu.Unlock()
	if ports != 0 || labels != 0 {
		t.Errorf("an ssh tunnel must not take a public port or label: %d ports, %d labels", ports, labels)
	}

	priv, ok := c.registerSSH("nas", true).(*proto.Registered)
	if !ok || !priv.Private || priv.Name != "nas" {
		t.Errorf("private registration: %+v", priv)
	}
	if e, isErr := c.registerSSH("nas", false).(*proto.Error); !isErr || e.Code != proto.CodeNameTaken {
		t.Errorf("duplicate name: %+v", e)
	}
	if e := c.registerErr(proto.KindSSH, "x", 20000); e.Code != proto.CodeInvalidRequest {
		t.Errorf("remote_port on ssh: %+v", e)
	}
}

func TestPrivateOnlyForSSH(t *testing.T) {
	h := newHarness(t, withGateway)
	c := h.login(h.st.newToken(t, "home"))
	for _, kind := range []string{proto.KindHTTP, proto.KindTCP} {
		c.reqID++
		if err := c.write(&proto.Register{ReqID: c.reqID, Kind: kind, Name: "x", Private: true}); err != nil {
			t.Fatal(err)
		}
		if e, ok := c.next().(*proto.Error); !ok || e.Code != proto.CodeInvalidRequest {
			t.Errorf("private on %s: %+v", kind, e)
		}
	}
}

func TestSSHScope(t *testing.T) {
	h := newHarness(t, withGateway)
	httpOnly := h.login(h.st.newToken(t, "web", func(tk *store.Token) { tk.Scopes = []string{auth.ScopeTunnelHTTP} }))
	if e, ok := httpOnly.registerSSH("", false).(*proto.Error); !ok || e.Code != proto.CodeForbidden {
		t.Errorf("ssh without tunnel:tcp: %+v", e)
	}
	tcpOnly := h.login(h.st.newToken(t, "raw", func(tk *store.Token) { tk.Scopes = []string{auth.ScopeTunnelTCP} }))
	if _, ok := tcpOnly.registerSSH("", false).(*proto.Registered); !ok {
		t.Error("tunnel:tcp must allow ssh tunnels")
	}
}

func TestLookupSSHTargets(t *testing.T) {
	h := newHarness(t, withGateway)
	home := h.login(h.st.newToken(t, "home"))
	sshReg := home.registerSSH("", false).(*proto.Registered)
	nasReg := home.registerSSH("nas", true).(*proto.Registered)
	home.mustRegister(proto.KindTCP, "db", 0)
	home.mustRegister(proto.KindHTTP, "web", 0)
	box := h.login(h.st.newToken(t, "my-box"))
	boxReg := box.registerSSH("", false).(*proto.Registered)
	devReg := box.registerSSH("dev", false).(*proto.Registered)

	tests := []struct {
		target string
		want   string // tunnel id, empty for "not found"
	}{
		{"home", sshReg.TunnelID},
		{"HOME", sshReg.TunnelID},
		{"home." + testDomain, sshReg.TunnelID},
		{"home." + testDomain + ".", sshReg.TunnelID},
		{"ssh-home", sshReg.TunnelID},
		{"nas-home", nasReg.TunnelID},
		{"nas-home." + testDomain, nasReg.TunnelID},
		{"my-box", boxReg.TunnelID},
		{"dev-my-box", devReg.TunnelID},
		{"dev-my-box." + testDomain, devReg.TunnelID},
		{"db-home", ""}, // a tcp tunnel is not reachable through the gateway
		{"web-home", ""},
		{"nas", ""},
		{"nas-box", ""},
		{"dev-home", ""},
		{"nobody", ""},
		{"", ""},
		{"-", ""},
		{"home.other.example", ""},
	}
	for _, tc := range tests {
		tun, ok := h.srv.lookupSSH(tc.target)
		switch {
		case tc.want == "" && ok:
			t.Errorf("lookupSSH(%q) = tunnel %s, want not found", tc.target, tun.id)
		case tc.want != "" && (!ok || tun.id != tc.want):
			t.Errorf("lookupSSH(%q) = %v, %v; want tunnel %s", tc.target, tun, ok, tc.want)
		}
	}
	if tun, _ := h.srv.lookupSSH("nas-home"); tun == nil || !tun.private || tun.sess.name != "home" {
		t.Errorf("nas-home: %+v", tun)
	}

	// A client that went away takes its tunnels with it.
	home.close()
	waitFor(t, "home to disappear", func() bool { _, ok := h.srv.lookupSSH("home"); return !ok })
}

func TestSSHOpenStream(t *testing.T) {
	h := newHarness(t, withGateway, func(cfg *config.Config, _ *Options) { cfg.SSHGateway.MaxConnsPerTunnel = 1 })
	echo := startEcho(t)
	c := h.login(h.st.newToken(t, "home"))
	c.registerSSH("", false)
	c.serve(forward(echo))

	tun, ok := h.srv.lookupSSH("home")
	if !ok {
		t.Fatal("tunnel not found")
	}
	if !tun.acquire() {
		t.Fatal("first slot must be free")
	}
	if tun.acquire() {
		t.Fatal("max_conns_per_tunnel = 1: the second slot must be refused")
	}
	defer tun.release()

	conn, err := tun.openStream("203.0.113.7:4242")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q, %v", buf, err)
	}
	hdr := <-c.headers
	if hdr.TunnelID != tun.id || hdr.RemoteAddr != "203.0.113.7:4242" {
		t.Errorf("stream header %+v", hdr)
	}
}
