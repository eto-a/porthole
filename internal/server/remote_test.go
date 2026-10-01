// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/transport"
)

func (h *harness) loginRemote(name string) *client {
	h.t.Helper()
	hello := goodHello(h.st.newToken(h.t, name).str)
	hello.Features = []string{proto.FeatureRemoteOpen}
	return loginWith(h.t, h.wsURL, hello, transport.DialOptions{})
}

func remoteErrCode(t *testing.T, err error) string {
	t.Helper()
	var re *adminapi.RemoteError
	if !errors.As(err, &re) {
		t.Fatalf("want *adminapi.RemoteError, got %T %v", err, err)
	}
	return re.Code
}

func TestRequestTunnelSuccess(t *testing.T) {
	h := newHarness(t)
	be := adminBackend{h.srv}
	c := h.loginRemote("home")

	type result struct {
		tun adminapi.RemoteTunnel
		err error
	}
	done := make(chan result, 1)
	go func() {
		tun, err := be.RequestTunnel(context.Background(), "home",
			adminapi.RemoteOpen{Kind: proto.KindHTTP, LocalAddr: "3000", Name: "web", RequestedBy: "tok1"})
		done <- result{tun, err}
	}()

	req, ok := c.next().(*proto.OpenRequest)
	if !ok || req.Kind != proto.KindHTTP || req.LocalAddr != "3000" || req.Name != "web" || req.RequestedBy != "tok1" || req.ReqID == 0 {
		t.Fatalf("open_request: %+v", req)
	}
	if err := c.write(&proto.OpenResult{ReqID: req.ReqID, OK: true, Tunnel: &proto.OpenedTunnel{
		Name: "web", Kind: proto.KindHTTP, PublicURL: "https://web-home.example.com",
	}}); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || r.tun.Name != "web" || r.tun.URL != "https://web-home.example.com" {
		t.Fatalf("result %+v, %v", r.tun, r.err)
	}
}

func TestRequestTunnelClientRefusal(t *testing.T) {
	h := newHarness(t)
	be := adminBackend{h.srv}
	c := h.loginRemote("home")

	done := make(chan error, 1)
	go func() {
		_, err := be.RequestTunnel(context.Background(), "home", adminapi.RemoteOpen{Kind: proto.KindTCP, LocalAddr: "22"})
		done <- err
	}()
	req := c.next().(*proto.OpenRequest)
	_ = c.write(&proto.OpenResult{ReqID: req.ReqID, Error: &proto.OpenError{Code: proto.CodeNotAllowed, Message: "allow_remote"}})
	if code := remoteErrCode(t, <-done); code != proto.CodeNotAllowed {
		t.Errorf("code %q", code)
	}

	// An unknown code from the client does not reach the operator as is.
	go func() {
		_, err := be.RequestTunnel(context.Background(), "home", adminapi.RemoteOpen{Kind: proto.KindTCP, LocalAddr: "22"})
		done <- err
	}()
	req = c.next().(*proto.OpenRequest)
	_ = c.write(&proto.OpenResult{ReqID: req.ReqID, Error: &proto.OpenError{Code: "made_up", Message: "x"}})
	if code := remoteErrCode(t, <-done); code != proto.CodeInternal {
		t.Errorf("unknown code mapped to %q", code)
	}
}

func TestRequestTunnelTimeout(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, o *Options) { o.RemoteOpenTimeout = 100 * time.Millisecond })
	be := adminBackend{h.srv}
	c := h.loginRemote("home")

	_, err := be.RequestTunnel(context.Background(), "home", adminapi.RemoteOpen{Kind: proto.KindHTTP, LocalAddr: "3000"})
	if code := remoteErrCode(t, err); code != proto.CodeTimeout {
		t.Fatalf("code %q", code)
	}
	// A late answer is ignored and the session keeps working.
	req := c.next().(*proto.OpenRequest)
	_ = c.write(&proto.OpenResult{ReqID: req.ReqID, OK: true, Tunnel: &proto.OpenedTunnel{Name: "web", Kind: proto.KindHTTP}})
	c.mustRegister(proto.KindHTTP, "web", 0)
}

func TestRequestTunnelUnsupportedAndOffline(t *testing.T) {
	h := newHarness(t)
	be := adminBackend{h.srv}
	ctx := context.Background()

	if _, err := be.RequestTunnel(ctx, "nobody", adminapi.RemoteOpen{Kind: proto.KindHTTP, LocalAddr: "1"}); !errors.Is(err, adminapi.ErrNotFound) {
		t.Errorf("offline client: %v", err)
	}
	c := h.login(h.st.newToken(t, "old")) // no features
	_, err := be.RequestTunnel(ctx, "old", adminapi.RemoteOpen{Kind: proto.KindHTTP, LocalAddr: "1"})
	if code := remoteErrCode(t, err); code != proto.CodeClientUnsupported {
		t.Errorf("code %q", code)
	}
	if _, err := be.RequestTunnel(ctx, "old", adminapi.RemoteOpen{Kind: "udp", LocalAddr: "1"}); remoteErrCode(t, err) != proto.CodeInvalidRequest {
		t.Errorf("bad kind: %v", err)
	}
	c.mustRegister(proto.KindHTTP, "web", 0) // nothing was sent to the old client
}

func TestRequestTunnelRemoteControlDisabled(t *testing.T) {
	h := newHarness(t)
	be := adminBackend{h.srv}
	hello := goodHello(h.st.newToken(t, "locked", func(tok *store.Token) { tok.RemoteControl = false }).str)
	hello.Features = []string{proto.FeatureRemoteOpen}
	c := loginWith(t, h.wsURL, hello, transport.DialOptions{})

	_, err := be.RequestTunnel(context.Background(), "locked", adminapi.RemoteOpen{Kind: proto.KindHTTP, LocalAddr: "3000"})
	if code := remoteErrCode(t, err); code != adminapi.CodeRemoteDisabled {
		t.Fatalf("code %q, want %q", code, adminapi.CodeRemoteDisabled)
	}
	c.mustRegister(proto.KindHTTP, "web", 0) // nothing was sent to the client
}
