// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/store"
)

type nopStore struct{ closed bool }

func (*nopStore) CreateToken(context.Context, *store.Token) error { return nil }
func (*nopStore) GetToken(context.Context, string) (*store.Token, error) {
	return nil, store.ErrNotFound
}
func (*nopStore) ListTokens(context.Context) ([]*store.Token, error)   { return nil, nil }
func (*nopStore) RevokeToken(context.Context, string, time.Time) error { return nil }
func (*nopStore) TouchToken(context.Context, string, time.Time) error  { return nil }
func (*nopStore) HoldPort(context.Context, string, string, int, time.Time, time.Duration) error {
	return nil
}
func (*nopStore) ReleasePort(context.Context, string, string, time.Time) error { return nil }
func (*nopStore) LoadPortReservations(context.Context, time.Time, time.Duration) ([]store.PortReservation, error) {
	return nil, nil
}
func (*nopStore) AppendAudit(context.Context, *store.AuditEntry) error { return nil }
func (*nopStore) ListAudit(context.Context, int) ([]store.AuditEntry, error) {
	return nil, nil
}
func (s *nopStore) Close() error { s.closed = true; return nil }

func testConfig() (*config.Config, error) {
	c := config.Default()
	c.Domain = "example.test"
	c.Listen = "127.0.0.1:0"
	c.DataDir = "unused"
	c.TLS.Mode = config.TLSModeOff
	c.ShutdownGrace = time.Second
	return c, nil
}

func TestServeStartsAndStops(t *testing.T) {
	st := &nopStore{}
	var stderr bytes.Buffer
	cmd := NewServe(testConfig, func(context.Context, *config.Config) (store.Store, error) { return st, nil }, "v-test")
	cmd.SetErr(&stderr)
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"--log-level", "debug"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: Run must still start, then shut down cleanly
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !st.closed {
		t.Error("store was not closed")
	}
	if out := stderr.String(); !strings.Contains(out, `"msg":"portholed starting"`) || !strings.Contains(out, `"version":"v-test"`) {
		t.Errorf("expected JSON startup log on stderr, got %q", out)
	}
}

func TestServeErrors(t *testing.T) {
	boom := errors.New("boom")
	openOK := func(context.Context, *config.Config) (store.Store, error) { return &nopStore{}, nil }
	cases := map[string]struct {
		load func() (*config.Config, error)
		open func(context.Context, *config.Config) (store.Store, error)
		args []string
		want string
	}{
		"bad log level": {testConfig, openOK, []string{"--log-level", "chatty"}, "--log-level"},
		"load fails":    {func() (*config.Config, error) { return nil, boom }, openOK, nil, "load config: boom"},
		"store fails": {
			testConfig, func(context.Context, *config.Config) (store.Store, error) { return nil, boom }, nil,
			"open store: boom",
		},
		"invalid config": {func() (*config.Config, error) { return config.Default(), nil }, openOK, nil, "domain"},
		"extra args":     {testConfig, openOK, []string{"surprise"}, "unknown command"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cmd := NewServe(tc.load, tc.open, "v")
			cmd.SetErr(io.Discard)
			cmd.SetOut(io.Discard)
			cmd.SetArgs(tc.args)
			err := cmd.ExecuteContext(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func (*nopStore) CreateJoinCode(context.Context, *store.JoinCode) error { return nil }
func (*nopStore) RedeemJoinCode(context.Context, string, string, time.Time) (*store.Token, string, error) {
	return nil, "", store.ErrNotFound
}
func (*nopStore) ListJoinCodes(context.Context) ([]*store.JoinCode, error) { return nil, nil }
func (*nopStore) RevokeJoinCode(context.Context, string, time.Time) error  { return nil }
