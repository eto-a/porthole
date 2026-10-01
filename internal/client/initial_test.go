// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/proto"
)

// runOpts runs Run against serverURL with the given initial-attempt limit and returns the event stream and the
// result of Run.
func runOpts(t *testing.T, serverURL string, maxInitial int) (events chan Event, done chan error, cancel context.CancelFunc) {
	t.Helper()
	events = make(chan Event, 256)
	done = make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	opts := Options{
		ServerURL:          serverURL,
		Token:              newToken(t),
		Tunnels:            []TunnelSpec{{Kind: proto.KindHTTP, LocalAddr: "127.0.0.1:8080"}},
		Version:            "test",
		Logger:             slog.New(slog.DiscardHandler),
		OnEvent:            func(e Event) { events <- e },
		MaxInitialAttempts: maxInitial,
	}
	go func() { done <- run(ctx, opts, testTuning()) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitFor):
			t.Error("Run did not return after cancel")
		}
	})
	return events, done, cancel
}

// deadURL returns the URL of a local address nothing listens on (connection refused).
func deadURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr
}

func TestInitialConnectGivesUpAfterMaxAttempts(t *testing.T) {
	events, done, _ := runOpts(t, deadURL(t), 3)

	select {
	case err := <-done:
		var ice *InitialConnectError
		if !errors.As(err, &ice) {
			t.Fatalf("Run returned %v, want *InitialConnectError", err)
		}
		if ice.Attempts != 3 {
			t.Errorf("Attempts = %d, want 3", ice.Attempts)
		}
		if ice.Err == nil || !errors.Is(err, ice.Err) {
			t.Errorf("error does not unwrap to the last attempt error: %v", err)
		}
		done <- err // let the cleanup see a finished Run
	case <-time.After(waitFor):
		t.Fatal("Run did not give up")
	}

	// Only the failures that were followed by a retry are reported: attempts 1 and 2 of 3.
	var got []Disconnected
	for len(events) > 0 {
		if d, ok := (<-events).(Disconnected); ok {
			got = append(got, d)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d Disconnected events, want 2: %+v", len(got), got)
	}
	for i, d := range got {
		if d.Attempt != i+1 || d.MaxAttempts != 3 {
			t.Errorf("event %d: Attempt/MaxAttempts = %d/%d, want %d/3", i, d.Attempt, d.MaxAttempts, i+1)
		}
	}
}

func TestInitialConnectUnlimitedKeepsRetrying(t *testing.T) {
	events, done, cancel := runOpts(t, deadURL(t), 0)

	for n := 1; n <= 6; n++ {
		select {
		case e := <-events:
			d, ok := e.(Disconnected)
			if !ok {
				t.Fatalf("unexpected event %+v", e)
			}
			if d.Attempt != n || d.MaxAttempts != 0 {
				t.Errorf("event %d: Attempt/MaxAttempts = %d/%d, want %d/0", n, d.Attempt, d.MaxAttempts, n)
			}
		case err := <-done:
			t.Fatalf("Run returned %v after %d attempts, want it to keep retrying", err, n-1)
		case <-time.After(waitFor):
			t.Fatalf("timed out waiting for attempt %d", n)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel, want nil", err)
		}
		done <- err
	case <-time.After(waitFor):
		t.Fatal("Run did not return after cancel")
	}
}

func TestInitialConnectTLSVerifyErrorFailsAtOnce(t *testing.T) {
	// A TLS server with a certificate the system does not trust; the limit is off, yet Run must not retry.
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	_, done, _ := runOpts(t, ts.URL, 0)

	select {
	case err := <-done:
		var ice *InitialConnectError
		if !errors.As(err, &ice) {
			t.Fatalf("Run returned %v, want *InitialConnectError", err)
		}
		if ice.Attempts != 1 {
			t.Errorf("Attempts = %d, want 1", ice.Attempts)
		}
		if !IsTLSVerifyError(err) {
			t.Errorf("error %v is not recognised as a TLS verification error", err)
		}
		done <- err
	case <-time.After(waitFor):
		t.Fatal("Run did not fail on the certificate error")
	}
}

func TestInitialConnectLimitDoesNotApplyAfterConnected(t *testing.T) {
	fs := newFakeServer(t)
	events, done, cancel := runOpts(t, fs.url(), 2)

	// Establish a session first.
	select {
	case e := <-events:
		if _, ok := e.(Connected); !ok {
			t.Fatalf("first event is %T, want Connected", e)
		}
	case err := <-done:
		t.Fatalf("Run returned %v before connecting", err)
	case <-time.After(waitFor):
		t.Fatal("timed out waiting for Connected")
	}

	// Take the server away: stop accepting and drop the live session. The client must keep retrying well past
	// the limit of 2, and these failures are plain reconnects (Attempt 0).
	_ = fs.ts.Listener.Close()
	_ = fs.conn(1).sess.Close()

	disconnects := 0
	deadline := time.After(waitFor)
	for disconnects < 5 {
		select {
		case e := <-events:
			if d, ok := e.(Disconnected); ok {
				disconnects++
				if d.Attempt != 0 || d.MaxAttempts != 0 {
					t.Errorf("Disconnected %d: Attempt/MaxAttempts = %d/%d, want 0/0", disconnects, d.Attempt, d.MaxAttempts)
				}
			}
		case err := <-done:
			t.Fatalf("Run returned %v after %d disconnects, want it to keep reconnecting", err, disconnects)
		case <-deadline:
			t.Fatalf("timed out after %d disconnects", disconnects)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel, want nil", err)
		}
		done <- err
	case <-time.After(waitFor):
		t.Fatal("Run did not return after cancel")
	}
}

func TestInitialConnectRetryableServerErrorsThenSuccess(t *testing.T) {
	// A server that rejects the first two connections with a retryable error and then accepts: with a limit of 3
	// the client must get through, and a later drop must not be counted as an initial failure.
	fs := newFakeServer(t)
	fs.handler = func(c *srvConn) {
		if c.n <= 2 {
			rejectHandler(&proto.Error{Code: proto.CodeShuttingDown, Message: "restarting", RetryAfterMS: 1})(c)
			return
		}
		fs.defaultHandler(c)
	}
	events, done, _ := runOpts(t, fs.url(), 3)

	deadline := time.After(waitFor)
	for {
		select {
		case e := <-events:
			if _, ok := e.(Connected); ok {
				if n := fs.connCount(); n != 3 {
					t.Fatalf("connected on connection %d, want 3", n)
				}
				return
			}
		case err := <-done:
			t.Fatalf("Run returned %v, want it to connect on the third attempt", err)
		case <-deadline:
			t.Fatal("timed out waiting for Connected")
		}
	}
}

func TestIsPermanentDialError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"no such host", &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}, true},
		{"wrapped no such host", fmt.Errorf("dial: %w", &net.OpError{Op: "dial", Err: &net.DNSError{IsNotFound: true}}), true},
		{"temporary dns failure", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, false},
		{"dns timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, false},
		{"connection refused", errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), false},
		{"deadline", context.DeadlineExceeded, false},
		{"tls verification", &tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")}, true},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPermanentDialError(tt.err); got != tt.want {
				t.Errorf("isPermanentDialError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestInitialConnectErrorMessage(t *testing.T) {
	err := &InitialConnectError{URL: "ws://127.0.0.1:1/x", Attempts: 5, Err: errors.New("boom")}
	want := "cannot connect to ws://127.0.0.1:1/x (5 failed attempt(s)): boom"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}
