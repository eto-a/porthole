// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package tokencmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/store"
)

type harness struct {
	t   *testing.T
	cfg *config.Config
	now time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domain = "tun.example.com"
	return &harness{t: t, cfg: cfg, now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
}

// run executes "token <args>" and returns stdout, stderr and the error.
func (h *harness) run(args ...string) (string, string, error) {
	h.t.Helper()
	cmd := newCmd(func() (*config.Config, error) { return h.cfg, nil }, func() time.Time { return h.now })
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func (h *harness) mustRun(args ...string) string {
	h.t.Helper()
	out, errOut, err := h.run(args...)
	if err != nil {
		h.t.Fatalf("token %v: %v\nstdout: %s\nstderr: %s", args, err, out, errOut)
	}
	return out
}

// create makes a token and returns the parsed token from the create output.
func (h *harness) create(args ...string) auth.Token {
	h.t.Helper()
	out := h.mustRun(append([]string{"create"}, args...)...)
	for _, f := range strings.Fields(out) {
		if tok, err := auth.Parse(f); err == nil {
			return tok
		}
	}
	h.t.Fatalf("no token in create output:\n%s", out)
	return auth.Token{}
}

func TestCreateListRevokeFlow(t *testing.T) {
	h := newHarness(t)

	createOut := h.mustRun("create", "--name", "home", "--expires", "30d", "--max-tunnels", "3")
	var tok auth.Token
	for _, f := range strings.Fields(createOut) {
		if p, err := auth.Parse(f); err == nil {
			tok = p
			break
		}
	}
	if tok.ID == "" {
		t.Fatalf("no token in output:\n%s", createOut)
	}
	if n := strings.Count(createOut, tok.Secret); n == 0 {
		t.Error("create output does not contain the secret")
	}
	for _, want := range []string{"only once", "porthole login https://tun.example.com " + tok.String(), "expires 2026-07-01 12:00 UTC"} {
		if !strings.Contains(createOut, want) {
			t.Errorf("create output lacks %q:\n%s", want, createOut)
		}
	}

	// The stored record has the right fields and no secret.
	st, err := store.Open(context.Background(), h.cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetToken(context.Background(), tok.ID)
	_ = st.Close()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "home" || rec.MaxTunnels != 3 || rec.Last4 != tok.Last4() ||
		!bytes.Equal(rec.SecretHash, tok.Hash()) || bytes.Contains(rec.SecretHash, []byte(tok.Secret)) {
		t.Errorf("record = %+v", rec)
	}
	if want := h.now.Add(30 * 24 * time.Hour); rec.ExpiresAt == nil || !rec.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", rec.ExpiresAt, want)
	}
	if strings.Join(rec.Scopes, ",") != strings.Join(auth.DefaultScopes, ",") {
		t.Errorf("scopes = %v, want defaults", rec.Scopes)
	}

	// list: table without the secret.
	listOut := h.mustRun("list")
	for _, want := range []string{
		"ID", "NAME", "SECRET", "SCOPES", "CREATED", "EXPIRES", "LAST USED", "STATUS",
		tok.ID, "home", "…" + tok.Last4(), "active", "never",
	} {
		if !strings.Contains(listOut, want) {
			t.Errorf("list lacks %q:\n%s", want, listOut)
		}
	}
	assertNoSecret(t, tok, listOut)

	// revoke by name.
	revokeOut := h.mustRun("revoke", "home")
	assertNoSecret(t, tok, revokeOut)
	for _, want := range []string{"Revoked", tok.ID, "30 seconds"} {
		if !strings.Contains(revokeOut, want) {
			t.Errorf("revoke output lacks %q:\n%s", want, revokeOut)
		}
	}

	// revoked tokens are hidden by default, shown with --all.
	if out := h.mustRun("list"); strings.Contains(out, tok.ID) || !strings.Contains(out, "No tokens") {
		t.Errorf("revoked token visible in default list:\n%s", out)
	}
	allOut := h.mustRun("list", "--all")
	if !strings.Contains(allOut, tok.ID) || !strings.Contains(allOut, "revoked") {
		t.Errorf("list --all:\n%s", allOut)
	}
	assertNoSecret(t, tok, allOut)

	// revoking again by id is a no-op with a message; by name it is not found any more.
	if out := h.mustRun("revoke", tok.ID); !strings.Contains(out, "already revoked") {
		t.Errorf("second revoke by id: %q", out)
	}
	if _, _, err := h.run("revoke", "home"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoke by revoked name: err = %v, want ErrNotFound", err)
	}

	// the name is reusable after revoke.
	h.create("--name", "home")
}

func assertNoSecret(t *testing.T, tok auth.Token, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		if strings.Contains(o, tok.Secret) || strings.Contains(o, tok.String()) {
			t.Errorf("secret leaked in output:\n%s", o)
		}
	}
}

func TestSecretOnlyInCreate(t *testing.T) {
	h := newHarness(t)
	tok := h.create("--name", "office-nas")
	for _, args := range [][]string{
		{"list"},
		{"list", "--all"},
		{"list", "--json"},
		{"list", "--all", "--json"},
		{"revoke", "office-nas"},
		{"revoke", tok.ID},
		{"list", "--all", "--json"},
	} {
		out, errOut, err := h.run(args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		assertNoSecret(t, tok, out, errOut)
		if strings.Contains(out, "secret_hash") || strings.Contains(out, "hash") {
			t.Errorf("%v: output mentions hash:\n%s", args, out)
		}
	}
}

func TestListJSON(t *testing.T) {
	h := newHarness(t)
	h.create("--name", "a", "--scopes", "tunnel:http", "--expires", "24h")
	h.now = h.now.Add(time.Minute) // distinct created_at keeps the list order deterministic
	b := h.create("--name", "b")
	h.now = h.now.Add(48 * time.Hour) // a is expired now
	h.mustRun("revoke", b.ID)

	var arr []map[string]any
	out := h.mustRun("list", "--all", "--json")
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(arr) != 2 {
		t.Fatalf("got %d entries, want 2:\n%s", len(arr), out)
	}
	if arr[0]["name"] != "a" || arr[0]["status"] != "expired" || arr[0]["revoked_at"] != nil {
		t.Errorf("entry a = %v", arr[0])
	}
	if sc, _ := arr[0]["scopes"].([]any); len(sc) != 1 || sc[0] != "tunnel:http" {
		t.Errorf("scopes = %v", arr[0]["scopes"])
	}
	if arr[1]["name"] != "b" || arr[1]["status"] != "revoked" || arr[1]["revoked_at"] == nil || arr[1]["expires_at"] != nil {
		t.Errorf("entry b = %v", arr[1])
	}
	if _, ok := arr[0]["last4"]; !ok {
		t.Error("last4 missing")
	}

	// Default hides revoked.
	out = h.mustRun("list", "--json")
	arr = nil
	if err := json.Unmarshal([]byte(out), &arr); err != nil || len(arr) != 1 {
		t.Errorf("default list: %v, %d entries\n%s", err, len(arr), out)
	}
	// Empty list is [] not null.
	h2 := newHarness(t)
	if out := strings.TrimSpace(h2.mustRun("list", "--json")); out != "[]" {
		t.Errorf("empty JSON list = %q, want []", out)
	}
}

func TestListStatusExpired(t *testing.T) {
	h := newHarness(t)
	h.create("--name", "short", "--expires", "1h")
	if out := h.mustRun("list"); !strings.Contains(out, "active") {
		t.Errorf("want active:\n%s", out)
	}
	h.now = h.now.Add(2 * time.Hour)
	out := h.mustRun("list")
	if !strings.Contains(out, "expired") {
		t.Errorf("want expired:\n%s", out)
	}
}

func TestCreateValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing name", []string{"create"}, "name"},
		{"empty name", []string{"create", "--name", ""}, "invalid --name"},
		{"uppercase name", []string{"create", "--name", "Home"}, "invalid --name"},
		{"dash edge", []string{"create", "--name", "-x"}, "invalid --name"},
		{"too long name", []string{"create", "--name", strings.Repeat("a", 33)}, "invalid --name"},
		{"bad scope", []string{"create", "--name", "x", "--scopes", "tunnel:http,admin"}, `unknown scope "admin"`},
		{"empty scopes", []string{"create", "--name", "x", "--scopes", ""}, "invalid --scopes"},
		{"bad expires", []string{"create", "--name", "x", "--expires", "soon"}, "invalid --expires"},
		{"negative expires", []string{"create", "--name", "x", "--expires", "-5d"}, "negative"},
		{"negative hours", []string{"create", "--name", "x", "--expires", "-1h"}, "negative"},
		{"huge expires", []string{"create", "--name", "x", "--expires", "999999d"}, "more than"},
		{"negative max", []string{"create", "--name", "x", "--max-tunnels", "-1"}, "--max-tunnels"},
		{"extra arg", []string{"create", "--name", "x", "extra"}, "unknown command"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			out, _, err := h.run(tc.args...)
			if err == nil {
				t.Fatalf("want error, got output:\n%s", out)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to contain %q", err, tc.want)
			}
			if strings.Contains(out, "ph_") {
				t.Errorf("token printed despite error:\n%s", out)
			}
			// Nothing was stored.
			if got := h.mustRun("list", "--all"); !strings.Contains(got, "No tokens") {
				t.Errorf("token stored despite error:\n%s", got)
			}
		})
	}
}

func TestCreateNameTaken(t *testing.T) {
	h := newHarness(t)
	h.create("--name", "home")
	out, _, err := h.run("create", "--name", "home")
	if !errors.Is(err, store.ErrNameTaken) {
		t.Fatalf("err = %v, want ErrNameTaken", err)
	}
	if strings.Contains(out, "ph_") {
		t.Errorf("token printed on failure:\n%s", out)
	}
}

func TestCreateScopesAndDedup(t *testing.T) {
	h := newHarness(t)
	tok := h.create("--name", "x", "--scopes", "tunnel:tcp,tunnel:http,tunnel:tcp")
	st, err := store.Open(context.Background(), h.cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rec, err := st.GetToken(context.Background(), tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rec.Scopes, ","); got != "tunnel:tcp,tunnel:http" {
		t.Errorf("scopes = %q", got)
	}
	if rec.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil for default --expires", rec.ExpiresAt)
	}
}

func TestCreateExpiresZeroIsNever(t *testing.T) {
	h := newHarness(t)
	h.mustRun("create", "--name", "x", "--expires", "0")
	if out := h.mustRun("list"); !strings.Contains(out, "never") {
		t.Errorf("expected never in list:\n%s", out)
	}
}

func TestLoginHint(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{"https default", func(*config.Config) {}, "porthole login https://tun.example.com ph_"},
		{"http with port", func(c *config.Config) { c.PublicScheme = "http"; c.PublicPort = 8080 }, "porthole login http://tun.example.com:8080 ph_"},
		{"server_url wins", func(c *config.Config) { c.PublicScheme = "http"; c.ServerURL = "https://tun.example.com" }, "porthole login https://tun.example.com ph_"},
		{"server_url trailing slash", func(c *config.Config) { c.ServerURL = "https://ctl.example.com:8443/" }, "porthole login https://ctl.example.com:8443 ph_"},
		{"no domain", func(c *config.Config) { c.Domain = "" }, "porthole login https://<domain> ph_"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.mutate(h.cfg)
			out := h.mustRun("create", "--name", "x")
			if !strings.Contains(out, tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out)
			}
		})
	}
}

func TestRevokeErrors(t *testing.T) {
	h := newHarness(t)
	if _, _, err := h.run("revoke", "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown: err = %v, want ErrNotFound", err)
	}
	if _, _, err := h.run("revoke"); err == nil {
		t.Error("no args: want error")
	}
	if _, _, err := h.run("revoke", "a", "b"); err == nil {
		t.Error("two args: want error")
	}
}

func TestRevokeByIDKeepsOthers(t *testing.T) {
	h := newHarness(t)
	a := h.create("--name", "a")
	h.create("--name", "b")
	h.mustRun("revoke", a.ID)
	out := h.mustRun("list")
	if strings.Contains(out, a.ID) || !strings.Contains(out, " b ") {
		t.Errorf("list after revoking a:\n%s", out)
	}
}

func TestConfigLoadedLazilyAndErrorsPropagate(t *testing.T) {
	calls := 0
	boom := errors.New("boom")
	cmd := New(func() (*config.Config, error) { calls++; return nil, boom })
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("config loaded %d times for --help, want 0", calls)
	}

	cmd.SetArgs([]string{"list"})
	cmd.SilenceUsage = true
	if err := cmd.Execute(); !errors.Is(err, boom) {
		t.Errorf("err = %v, want boom", err)
	}
	if calls != 1 {
		t.Errorf("config loaded %d times, want 1", calls)
	}
}

func TestParseExpires(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"1.5d", 36 * time.Hour, false},
		{"720h", 720 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"1h30m", 90 * time.Minute, false},
		{" 7d ", 7 * 24 * time.Hour, false},
		{"0d", 0, true},
		{"-1d", 0, true},
		{"-1h", 0, true},
		{"d", 0, true},
		{"xd", 0, true},
		{"NaNd", 0, true},
		{"Infd", 0, true},
		{"36501d", 0, true},
		{"1000000h", 0, true},
		{"abc", 0, true},
		{"10", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseExpires(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
