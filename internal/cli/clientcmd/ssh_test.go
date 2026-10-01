// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/proto"
)

func TestSSHCommandGateway(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var got client.Options
	d := capture(testDeps(nil), &got,
		client.Connected{ClientName: "home"},
		client.TunnelReady{
			Spec:    client.TunnelSpec{Kind: proto.KindSSH, Name: "ssh", LocalAddr: "127.0.0.1:22"},
			Name:    "ssh",
			SSHJump: "tun.example.com:2222",
		})

	stdout, _, err := execute(t, d, "--config", path, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tunnels[0] != (client.TunnelSpec{Kind: "ssh", Name: "ssh", LocalAddr: "127.0.0.1:22"}) {
		t.Fatalf("tunnels %+v", got.Tunnels)
	}
	for _, want := range []string{"ssh -J tun.example.com:2222 alice@home", "Host home", "ProxyJump tun.example.com:2222"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout %q lacks %q", stdout, want)
		}
	}
}

func TestSSHCommandPrivateAndNamed(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var got client.Options
	d := capture(testDeps(nil), &got,
		client.Connected{ClientName: "home"},
		client.TunnelReady{
			Spec:    client.TunnelSpec{Kind: proto.KindSSH, Name: "nas", LocalAddr: "127.0.0.1:22", Private: true},
			Name:    "nas",
			SSHJump: "tun.example.com:2222",
		})

	stdout, _, err := execute(t, d, "--config", path, "ssh", "--private", "--name", "nas", "--user", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tunnels[0] != (client.TunnelSpec{Kind: "ssh", Name: "nas", LocalAddr: "127.0.0.1:22", Private: true}) {
		t.Fatalf("tunnels %+v", got.Tunnels)
	}
	if !strings.Contains(stdout, "ssh -J tun.example.com:2222 bob@nas-home") || !strings.Contains(stdout, "porthole token") {
		t.Errorf("stdout %q", stdout)
	}
}

func TestSSHCommandFlagConflicts(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	d := testDeps(nil)
	for _, args := range [][]string{
		{"ssh", "--private", "--public-port"},
		{"ssh", "--remote-port", "20017"},
	} {
		if _, _, err := execute(t, d, append([]string{"--config", path}, args...)...); err == nil {
			t.Errorf("%v must be rejected", args)
		}
	}
}

// refuseSSH returns deps whose run answers the first call (kind ssh) with the given error and records all calls.
func refuseSSH(d deps, calls *[]client.TunnelSpec, refusal error, events ...client.Event) deps {
	d.run = func(_ context.Context, o client.Options) error {
		*calls = append(*calls, o.Tunnels[0])
		if o.Tunnels[0].Kind == proto.KindSSH {
			return refusal
		}
		for _, e := range events {
			o.OnEvent(e)
		}
		return nil
	}
	return d
}

func TestSSHCommandFallsBackToPublicPort(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var calls []client.TunnelSpec
	refusal := fmt.Errorf("register tunnel \"ssh\": %w", &proto.Error{Code: proto.CodeInvalidRequest, Message: "unknown tunnel kind"})
	d := refuseSSH(testDeps(nil), &calls, refusal, client.TunnelReady{
		Spec: client.TunnelSpec{Kind: proto.KindTCP, Name: "ssh", LocalAddr: "127.0.0.1:22"}, Name: "ssh",
		PublicURL: "tcp://tun.example.com:20018",
	})

	stdout, stderr, err := execute(t, d, "--config", path, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0].Kind != proto.KindSSH || calls[1].Kind != proto.KindTCP {
		t.Fatalf("calls %+v", calls)
	}
	if !strings.Contains(stderr, "warning") || !strings.Contains(stderr, "unknown tunnel kind") {
		t.Errorf("stderr %q", stderr)
	}
	if !strings.Contains(stdout, "ssh -p 20018 alice@tun.example.com") {
		t.Errorf("stdout %q", stdout)
	}
}

func TestSSHCommandPrivateNeverFallsBack(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var calls []client.TunnelSpec
	refusal := &proto.Error{Code: proto.CodeInvalidRequest, Message: "unknown tunnel kind"}
	d := refuseSSH(testDeps(nil), &calls, refusal)

	_, _, err := execute(t, d, "--config", path, "ssh", "--private")
	if err == nil {
		t.Fatal("--private against a server without ssh support must fail")
	}
	if len(calls) != 1 {
		t.Fatalf("calls %+v: --private must not retry with a public port", calls)
	}
}

func TestSSHCommandOtherErrorsDoNotFallBack(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var calls []client.TunnelSpec
	d := refuseSSH(testDeps(nil), &calls, &proto.Error{Code: proto.CodeForbidden, Message: "token lacks scope"})

	if _, _, err := execute(t, d, "--config", path, "ssh"); err == nil {
		t.Fatal("forbidden must fail")
	}
	if len(calls) != 1 {
		t.Fatalf("calls %+v", calls)
	}
}
