// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
)

const testServerURL = "https://tun.example.com"

func joinEnv(t *testing.T, tokens map[string][]string) *env {
	t.Helper()
	e := newEnv(t, tokens)
	e.api.serverURL = testServerURL + "/"
	return e
}

// post sends a JSON body to the admin API.
func (e *env) post(h http.Handler, path, bearer, body string) (int, string) {
	req := httptest.NewRequest(http.MethodPost, Prefix+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func decodeCreated(t *testing.T, body string) JoinCreated {
	t.Helper()
	var c JoinCreated
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return c
}

func TestJoinCreateListRevoke(t *testing.T) {
	e := joinEnv(t, nil)
	h := e.api.SocketHandler()

	st, body := e.post(h, "/join", "", `{"client_name":"home","max_tunnels":2,"token_expires_in":"30d"}`)
	if st != http.StatusOK {
		t.Fatalf("create: %d %s", st, body)
	}
	c := decodeCreated(t, body)
	code, ok := strings.CutPrefix(c.Link, testServerURL+"/j/")
	if !ok {
		t.Fatalf("link %q does not start with the server URL and /j/", c.Link)
	}
	parsed, err := auth.ParseJoin(code)
	if err != nil || parsed.ID != c.ID {
		t.Fatalf("link code %q: %v (id %q)", code, err, c.ID)
	}
	if c.Command != "porthole join "+c.Link || c.ClientName != "home" {
		t.Errorf("created = %+v", c)
	}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if !c.ExpiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("expires_at = %v, want now+15m (the default)", c.ExpiresAt)
	}

	// The store holds a hash that verifies the code and the defaults.
	jc := e.st.joins[0]
	if !auth.Verify(parsed.Secret, jc.CodeHash) || !jc.RemoteControl || jc.CreatedBy != ActorSocket || jc.MaxTunnels != 2 ||
		jc.TokenExpiresAt == nil || !jc.TokenExpiresAt.Equal(now.Add(30*24*time.Hour)) || strings.Join(jc.Scopes, ",") != strings.Join(auth.DefaultScopes, ",") {
		t.Errorf("stored code = %+v", jc)
	}

	st, body, _ = e.do(h, http.MethodGet, "/join", "")
	if st != http.StatusOK || !strings.Contains(body, `"client_name":"home"`) || !strings.Contains(body, `"status":"active"`) {
		t.Fatalf("list: %d %s", st, body)
	}
	if strings.Contains(body, parsed.Secret) || strings.Contains(body, "code_hash") {
		t.Errorf("list leaks the secret or the hash: %s", body)
	}

	if st, body = e.post(h, "/join/"+c.ID+"/revoke", "", ""); st != http.StatusOK {
		t.Fatalf("revoke: %d %s", st, body)
	}
	if e.st.joins[0].RevokedAt == nil {
		t.Error("code not revoked in the store")
	}
	if st, body = e.post(h, "/join/unknownidxxxx/revoke", "", ""); st != http.StatusNotFound {
		t.Errorf("revoke unknown: %d %s, want 404", st, body)
	}
}

func TestJoinCreateOptions(t *testing.T) {
	e := joinEnv(t, nil)
	h := e.api.SocketHandler()
	st, body := e.post(h, "/join", "", `{"client_name":"lab","ttl":"2h","remote_control":false,"scopes":["tunnel:http","connect:home"]}`)
	if st != http.StatusOK {
		t.Fatalf("%d %s", st, body)
	}
	jc := e.st.joins[0]
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if jc.RemoteControl || !jc.ExpiresAt.Equal(now.Add(2*time.Hour)) || len(jc.Scopes) != 2 || jc.TokenExpiresAt != nil {
		t.Errorf("stored code = %+v", jc)
	}
}

func TestJoinCreateValidation(t *testing.T) {
	e := joinEnv(t, nil)
	h := e.api.SocketHandler()
	for name, body := range map[string]string{ //nolint:gosec // request bodies, not credentials
		"no name":            `{}`,
		"bad name":           `{"client_name":"Bad Name"}`,
		"unknown scope":      `{"client_name":"a","scopes":["root"]}`,
		"negative tunnels":   `{"client_name":"a","max_tunnels":-1}`,
		"ttl too short":      `{"client_name":"a","ttl":"1s"}`,
		"ttl too long":       `{"client_name":"a","ttl":"30d"}`,
		"ttl garbage":        `{"client_name":"a","ttl":"soon"}`,
		"token expires soon": `{"client_name":"a","ttl":"1h","token_expires_in":"30m"}`,
		"unknown field":      `{"client_name":"a","admin":true}`,
		"not json":           `nope`,
	} {
		if st, resp := e.post(h, "/join", "", body); st != http.StatusBadRequest || errCode(t, resp) != "invalid_request" {
			t.Errorf("%s: %d %s, want 400 invalid_request", name, st, resp)
		}
	}
	if len(e.st.joins) != 0 {
		t.Errorf("%d codes stored by rejected requests", len(e.st.joins))
	}
}

func TestJoinNameConflict(t *testing.T) {
	e := joinEnv(t, map[string][]string{"adm": {auth.ScopeAdminTokens}})
	h := e.api.SocketHandler()
	// The fake store names its tokens "n-<id>".
	if st, resp := e.post(h, "/join", "", `{"client_name":"n-adm"}`); st != http.StatusConflict || errCode(t, resp) != "conflict" {
		t.Errorf("%d %s, want 409 conflict", st, resp)
	}
}

func TestJoinScopes(t *testing.T) {
	e := joinEnv(t, map[string][]string{
		"tok": {auth.ScopeAdminTokens},
		"rd":  {auth.ScopeAdminRead},
		"rdt": {auth.ScopeAdminTokens, auth.ScopeAdminRead},
	})
	h := e.api.BearerHandler()
	bearer := func(id string) string { return "ph_" + id + "_secret" }

	if st, resp := e.post(h, "/join", bearer("rd"), `{"client_name":"a"}`); st != http.StatusForbidden {
		t.Errorf("create without admin:tokens: %d %s, want 403", st, resp)
	}
	if st, _, _ := e.do(h, http.MethodGet, "/join", bearer("rd")); st != http.StatusForbidden {
		t.Errorf("list without admin:tokens: %d, want 403", st)
	}
	if st, _ := e.post(h, "/join/xxxxxxxxxxxx/revoke", bearer("rd"), ""); st != http.StatusForbidden {
		t.Errorf("revoke without admin:tokens: %d, want 403", st)
	}
	if st, resp := e.post(h, "/join", bearer("tok"), `{"client_name":"a"}`); st != http.StatusOK {
		t.Errorf("create with admin:tokens: %d %s", st, resp)
	}
	// No privilege escalation: a token may hand out tunnel scopes, but only the other scopes it holds itself.
	if st, resp := e.post(h, "/join", bearer("tok"), `{"client_name":"b","scopes":["admin:traffic"]}`); st != http.StatusForbidden {
		t.Errorf("grant a scope it lacks: %d %s, want 403", st, resp)
	}
	if st, resp := e.post(h, "/join", bearer("rdt"), `{"client_name":"c","scopes":["admin:read"]}`); st != http.StatusOK {
		t.Errorf("grant a scope it holds: %d %s", st, resp)
	}
	if got := e.st.joins[len(e.st.joins)-1].CreatedBy; got != "rdt" {
		t.Errorf("created_by = %q, want the token id", got)
	}
}

func TestJoinAudit(t *testing.T) {
	e := joinEnv(t, map[string][]string{"tok": {auth.ScopeAdminTokens}, "rd": {auth.ScopeAdminRead}})
	h := e.api.BearerHandler()
	bearer := func(id string) string { return "ph_" + id + "_secret" }

	_, body := e.post(h, "/join", bearer("tok"), `{"client_name":"home"}`)
	c := decodeCreated(t, body)
	e.post(h, "/join", bearer("rd"), `{"client_name":"x"}`)    // denied
	e.post(h, "/join", bearer("tok"), `{"client_name":"Bad"}`) // invalid
	e.post(h, "/join/"+c.ID+"/revoke", bearer("tok"), "")      // revoke

	var got []string
	for _, a := range e.st.audit {
		got = append(got, a.Actor+" "+a.Action+" "+a.Target+" "+a.Result)
	}
	want := []string{
		"tok join.create " + c.ID + " ok",
		"rd join.create  denied",
		"tok join.create  error: invalid_request",
		"tok join.revoke " + c.ID + " ok",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("audit =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	secret := strings.TrimPrefix(c.Link, testServerURL+"/j/")
	for _, a := range e.st.audit {
		if strings.Contains(a.Args, secret) || strings.Contains(a.Args, "pj_") {
			t.Errorf("audit args hold the code: %s", a.Args)
		}
	}
}
