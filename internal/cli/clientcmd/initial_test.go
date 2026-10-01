// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/client"
)

func TestMaxInitialAttemptsFlag(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"default", nil, client.DefaultMaxInitialAttempts},
		{"explicit", []string{"--max-initial-attempts", "2"}, 2},
		{"unlimited", []string{"--max-initial-attempts", "0"}, 0},
		{"negative means unlimited", []string{"--max-initial-attempts", "-1"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got client.Options
			d := capture(testDeps(nil), &got)
			args := append([]string{"--config", path, "http", "8080"}, tt.args...)
			if _, _, err := execute(t, d, args...); err != nil {
				t.Fatal(err)
			}
			if got.MaxInitialAttempts != tt.want {
				t.Errorf("MaxInitialAttempts = %d, want %d", got.MaxInitialAttempts, tt.want)
			}
		})
	}
	if client.DefaultMaxInitialAttempts <= 0 {
		t.Errorf("the default limit must be positive, got %d", client.DefaultMaxInitialAttempts)
	}
}

func TestInitialAttemptEventIsPrinted(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var got client.Options
	d := capture(testDeps(nil), &got,
		client.Disconnected{Err: errors.New("refused"), RetryIn: time.Second, Attempt: 2, MaxAttempts: 5},
		client.Disconnected{Err: errors.New("refused"), RetryIn: time.Second, Attempt: 3},
		client.Disconnected{Err: errors.New("lost"), RetryIn: time.Second},
	)
	_, stderr, err := execute(t, d, "--config", path, "http", "8080")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cannot connect (attempt 2 of 5), retrying in 1s: refused",
		"cannot connect (attempt 3 of unlimited), retrying in 1s: refused",
		"reconnecting in 1s: lost",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q does not contain %q", stderr, want)
		}
	}
}

func TestInitialConnectErrorIsExplained(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	tests := []struct {
		name  string
		inner error
		want  []string
	}{
		{
			"refused", errors.New("dial tcp 127.0.0.1:1: connect: connection refused"),
			[]string{"after 5 attempt(s)", "connection refused", "portholed is running", "firewall", "--max-initial-attempts 0"},
		},
		{
			"dns", fmt.Errorf("dial: %w", &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}),
			[]string{"does not resolve", "typos"},
		},
		{
			"tls", &tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")},
			[]string{"certificate could not be verified"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ice := &client.InitialConnectError{URL: "wss://tun.example.com/x", Attempts: 5, Err: tt.inner}
			d := testDeps(nil)
			d.run = func(context.Context, client.Options) error { return ice }
			_, _, err := execute(t, d, "--config", path, "http", "8080")
			if err == nil {
				t.Fatal("want an error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
			var got *client.InitialConnectError
			if !errors.As(err, &got) || got != ice {
				t.Error("the original error is not reachable through errors.As")
			}
		})
	}
}
