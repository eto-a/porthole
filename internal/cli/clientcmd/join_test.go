// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/proto"
)

func joinCode(t *testing.T) string {
	t.Helper()
	g, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return g.JoinString()
}

// joinServer answers POST JoinPath: the code is checked against want, the reply is the token (or the error).
func joinServer(t *testing.T, want, token string, fail *proto.Error, failStatus int) (*httptest.Server, *int) {
	t.Helper()
	calls := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		var req proto.JoinRequest
		if r.Method != http.MethodPost || r.URL.Path != proto.JoinPath || json.NewDecoder(r.Body).Decode(&req) != nil || req.Code != want {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if fail != nil {
			w.WriteHeader(failStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": fail.Code, "message": fail.Message}})
			return
		}
		_ = json.NewEncoder(w).Encode(proto.JoinResponse{ServerURL: "https://ignored.example", ClientName: "laptop", Token: token})
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

func TestJoinWithLinkSavesConfig(t *testing.T) {
	code, token := joinCode(t), testToken(t)
	srv, calls := joinServer(t, code, token, nil, 0)
	path := filepath.Join(t.TempDir(), "porthole", "config.yaml")

	stdout, _, err := execute(t, testDeps(nil), "--config", path, "join", srv.URL+"/j/"+code)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if !strings.Contains(stdout, "joined as laptop") || strings.Contains(stdout, token) {
		t.Errorf("stdout = %q", stdout)
	}
	fc, err := loadConfig(path)
	if err != nil || fc.Server != srv.URL || fc.Token != token {
		t.Errorf("config = %+v, %v; want the link's server and the new token", fc, err)
	}
	if *calls != 1 {
		t.Errorf("server calls = %d, want 1", *calls)
	}
}

func TestJoinWithBareCode(t *testing.T) {
	code, token := joinCode(t), testToken(t)
	srv, _ := joinServer(t, code, token, nil, 0)
	dir := t.TempDir()

	// No server anywhere: a usage error before any request.
	_, _, err := execute(t, testDeps(nil), "--config", filepath.Join(dir, "a.yaml"), "join", code)
	var ee *exitcode.Error
	if !errors.As(err, &ee) || ee.Code != exitcode.Usage {
		t.Errorf("bare code without a server: %v, want a usage error", err)
	}

	for name, run := range map[string]func() error{
		"flag": func() error {
			_, _, err := execute(t, testDeps(nil), "--config", filepath.Join(dir, "b.yaml"), "join", "--server", srv.URL+"/", code)
			return err
		},
		"env": func() error {
			_, _, err := execute(t, testDeps(map[string]string{envServer: srv.URL}), "--config", filepath.Join(dir, "c.yaml"), "join", code)
			return err
		},
		"existing config": func() error {
			p := writeConfig(t, srv.URL, testToken(t))
			_, _, err := execute(t, testDeps(nil), "--config", p, "join", code)
			return err
		},
	} {
		if err := run(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	fc, _ := loadConfig(filepath.Join(dir, "b.yaml"))
	if fc.Server != srv.URL || fc.Token != token {
		t.Errorf("config = %+v", fc)
	}
}

func TestJoinJSONHasNoToken(t *testing.T) {
	code, token := joinCode(t), testToken(t)
	srv, _ := joinServer(t, code, token, nil, 0)
	path := filepath.Join(t.TempDir(), "config.yaml")

	stdout, _, err := execute(t, testDeps(nil), "--config", path, "--json", "join", srv.URL+"/j/"+code)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, token) || strings.Contains(stdout, "token") {
		t.Errorf("json output mentions the token: %s", stdout)
	}
	var got joinResult
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || !got.Joined || got.ClientName != "laptop" || got.Server != srv.URL || got.Config != path {
		t.Errorf("json = %s (%v)", stdout, err)
	}
}

func TestJoinRefusals(t *testing.T) {
	code := joinCode(t)
	for _, c := range []struct {
		name   string
		status int
		code   string
		exit   int
	}{
		{"used", http.StatusGone, proto.CodeJoinUsed, exitcode.Auth},
		{"expired", http.StatusGone, proto.CodeJoinExpired, exitcode.Auth},
		{"unknown", http.StatusNotFound, proto.CodeInvalidJoinCode, exitcode.Auth},
		{"name taken", http.StatusConflict, proto.CodeNameTaken, exitcode.Rejected},
	} {
		srv, _ := joinServer(t, code, "", &proto.Error{Code: c.code, Message: "no"}, c.status)
		path := filepath.Join(t.TempDir(), "config.yaml")
		_, _, err := execute(t, testDeps(nil), "--config", path, "join", srv.URL+"/j/"+code)
		var ee *exitcode.Error
		if !errors.As(err, &ee) || ee.Code != c.exit || !strings.Contains(err.Error(), c.code) {
			t.Errorf("%s: err = %v, want exit %d mentioning %s", c.name, err, c.exit, c.code)
		}
		if fc, _ := loadConfig(path); fc.Token != "" {
			t.Errorf("%s: credentials were saved after a refusal", c.name)
		}
	}

	// Nothing listens: a connect failure, not a usage error.
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	_, _, err := execute(t, testDeps(nil), "--config", filepath.Join(t.TempDir(), "c.yaml"), "join", url+"/j/"+code)
	var ee *exitcode.Error
	if !errors.As(err, &ee) || ee.Code != exitcode.Connect {
		t.Errorf("unreachable server: %v, want a connect error", err)
	}
}

func TestJoinRejectsBadInput(t *testing.T) {
	good := joinCode(t)
	for _, arg := range []string{
		"nonsense",
		"https://tun.example.com/j/",
		"https://tun.example.com/other/" + good,
		"https://tun.example.com/j/ph_abc_def",
		"ftp://tun.example.com/j/" + good,
		"https:///j/" + good,
	} {
		_, _, err := execute(t, testDeps(nil), "--config", filepath.Join(t.TempDir(), "c.yaml"), "join", arg)
		var ee *exitcode.Error
		if !errors.As(err, &ee) || ee.Code != exitcode.Usage {
			t.Errorf("join %q: %v, want a usage error", arg, err)
		}
	}
}

func TestParseJoinTarget(t *testing.T) {
	code := joinCode(t)
	base, got, err := parseJoinTarget("https://tun.example.com:8443/prefix/j/"+code, "")
	if err != nil || base != "https://tun.example.com:8443/prefix" || got != code {
		t.Errorf("link with a path prefix: %q %q %v", base, got, err)
	}
	if base, _, err := parseJoinTarget(" "+code+" ", "http://127.0.0.1:8080/"); err != nil || base != "http://127.0.0.1:8080" {
		t.Errorf("code with a fallback: %q %v", base, err)
	}
}
