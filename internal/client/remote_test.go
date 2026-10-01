// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/proto"
)

// remoteAsk sends an open_request on the first connection and returns the client's answer.
func remoteAsk(t *testing.T, fs *fakeServer, req *proto.OpenRequest) *proto.OpenResult {
	t.Helper()
	c := fs.conn(1)
	if err := c.send(req); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-c.openResCh:
		if res.ReqID != req.ReqID {
			t.Fatalf("answer for request %d, asked %d", res.ReqID, req.ReqID)
		}
		return res
	case <-time.After(waitFor):
		t.Fatal("no open_result")
		return nil
	}
}

func remoteMgr(t *testing.T, fs *fakeServer, accept bool, policy *RemotePolicy) *mgrHarness {
	t.Helper()
	h := startMgr(t, fs, nil, testTuning(), func(o *Options) {
		o.AcceptRemoteOpen = accept
		o.RemoteOpen = policy
	})
	nextEv[Connected](t, h)
	return h
}

func TestRemoteOpenAnnouncesFeature(t *testing.T) {
	fs := newFakeServer(t)
	remoteMgr(t, fs, true, nil)
	if f := fs.conn(1).hello.Features; len(f) != 1 || f[0] != proto.FeatureRemoteOpen {
		t.Errorf("features %v", f)
	}
	fs2 := newFakeServer(t)
	remoteMgr(t, fs2, false, nil)
	if f := fs2.conn(1).hello.Features; len(f) != 0 {
		t.Errorf("features %v, want none", f)
	}
}

func TestRemoteOpenOpensTunnel(t *testing.T) {
	fs := newFakeServer(t)
	h := remoteMgr(t, fs, true, nil)

	res := remoteAsk(t, fs, &proto.OpenRequest{ReqID: 7, Kind: proto.KindHTTP, LocalAddr: "3000", Name: "web", RequestedBy: "tok"})
	if !res.OK || res.Tunnel == nil || res.Tunnel.Name != "web" || res.Tunnel.PublicURL != "https://web-home.tun.test" {
		t.Fatalf("result %+v %+v", res, res.Error)
	}
	ts, ok := tunnelOf(h.m, "web")
	if !ok || ts.Status != StatusReady || ts.Spec.LocalAddr != "127.0.0.1:3000" {
		t.Fatalf("tunnel %+v", ts)
	}

	// ssh without an address is 127.0.0.1:22, and reports the gateway.
	res = remoteAsk(t, fs, &proto.OpenRequest{ReqID: 8, Kind: proto.KindSSH, Private: true})
	if !res.OK || res.Tunnel.SSHJump != "tun.test:2222" {
		t.Fatalf("ssh result %+v %+v", res, res.Error)
	}
	if ts, _ := tunnelOf(h.m, "ssh"); ts.Spec.LocalAddr != DefaultSSHAddr || !ts.Spec.Private {
		t.Errorf("ssh tunnel %+v", ts)
	}

	// The tunnel exists already: the answer says so and the first one is untouched.
	res = remoteAsk(t, fs, &proto.OpenRequest{ReqID: 9, Kind: proto.KindHTTP, LocalAddr: "3001", Name: "web"})
	if res.OK || res.Error == nil || res.Error.Code != proto.CodeNameTaken {
		t.Fatalf("duplicate: %+v %+v", res, res.Error)
	}
}

func TestRemoteOpenRefusedByServerIsRemoved(t *testing.T) {
	fs := newFakeServer(t)
	fs.regError = func(_ int, _ *proto.Register) *proto.Error {
		return &proto.Error{Code: proto.CodeLimitExceeded, Message: "too many tunnels"}
	}
	h := remoteMgr(t, fs, true, nil)
	res := remoteAsk(t, fs, &proto.OpenRequest{ReqID: 1, Kind: proto.KindHTTP, LocalAddr: "3000", Name: "web"})
	if res.OK || res.Error == nil || res.Error.Code != proto.CodeLimitExceeded {
		t.Fatalf("result %+v %+v", res, res.Error)
	}
	if _, ok := tunnelOf(h.m, "web"); ok {
		t.Error("the failed tunnel stays in the set and would be retried on every reconnect")
	}
}

func TestRemoteOpenPolicy(t *testing.T) {
	cases := []struct {
		name   string
		policy *RemotePolicy
		local  string
		kind   string
		allow  bool
	}{
		{"nil allows all", nil, "5000", proto.KindHTTP, true},
		{"none refuses", &RemotePolicy{}, "3000", proto.KindHTTP, false},
		{"listed port", &RemotePolicy{Targets: []string{"127.0.0.1:3000"}}, "3000", proto.KindHTTP, true},
		{"other port", &RemotePolicy{Targets: []string{"127.0.0.1:3000"}}, "3001", proto.KindHTTP, false},
		{"other host", &RemotePolicy{Targets: []string{"127.0.0.1:80"}}, "192.168.1.5:80", proto.KindHTTP, false},
		{"lan host", &RemotePolicy{Targets: []string{"192.168.1.5:80"}}, "192.168.1.5:80", proto.KindTCP, true},
		{"ssh default", &RemotePolicy{Targets: []string{DefaultSSHAddr}}, "", proto.KindSSH, true},
		{"ssh alias", &RemotePolicy{Targets: []string{DefaultSSHAddr}}, "ssh", proto.KindSSH, true},
		{"ssh not listed", &RemotePolicy{Targets: []string{"127.0.0.1:3000"}}, "", proto.KindSSH, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeServer(t)
			h := remoteMgr(t, fs, true, tc.policy)
			res := remoteAsk(t, fs, &proto.OpenRequest{ReqID: 1, Kind: tc.kind, LocalAddr: tc.local})
			if res.OK != tc.allow {
				t.Fatalf("ok=%v, want %v (%+v)", res.OK, tc.allow, res.Error)
			}
			if !tc.allow {
				if res.Error == nil || res.Error.Code != proto.CodeNotAllowed {
					t.Errorf("error %+v", res.Error)
				}
				if n := len(h.m.Snapshot().Tunnels); n != 0 {
					t.Errorf("%d tunnels were added despite the refusal", n)
				}
			}
		})
	}
}

func TestRemoteOpenPolicyChange(t *testing.T) {
	fs := newFakeServer(t)
	h := remoteMgr(t, fs, true, nil)
	h.m.SetRemoteOpen(&RemotePolicy{})
	if res := remoteAsk(t, fs, &proto.OpenRequest{ReqID: 1, Kind: proto.KindHTTP, LocalAddr: "3000"}); res.OK {
		t.Fatal("request allowed after SetRemoteOpen(none)")
	}
}

func TestRemoteOpenWithoutFeatureIsRefused(t *testing.T) {
	fs := newFakeServer(t)
	remoteMgr(t, fs, false, nil)
	res := remoteAsk(t, fs, &proto.OpenRequest{ReqID: 1, Kind: proto.KindHTTP, LocalAddr: "3000"})
	if res.OK || res.Error == nil || res.Error.Code != proto.CodeClientUnsupported {
		t.Fatalf("result %+v %+v", res, res.Error)
	}
}

func TestRemoteOpenInvalid(t *testing.T) {
	fs := newFakeServer(t)
	remoteMgr(t, fs, true, nil)
	for i, req := range []*proto.OpenRequest{
		{Kind: "udp", LocalAddr: "1"},
		{Kind: proto.KindHTTP, LocalAddr: "not a port"},
		{Kind: proto.KindHTTP, LocalAddr: "3000", Name: "Bad Name"},
		{Kind: proto.KindHTTP},
	} {
		req.ReqID = i + 1
		if res := remoteAsk(t, fs, req); res.OK || res.Error == nil || res.Error.Code != proto.CodeInvalidRequest {
			t.Errorf("%+v: %+v %+v", req, res, res.Error)
		}
	}
}
