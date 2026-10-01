// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
)

var secNow = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func lastJoin(t *testing.T, e *env) (scopes []string, tokExp *time.Time, expires time.Time, maxTunnels int) {
	t.Helper()
	if len(e.st.joins) == 0 {
		t.Fatal("no join code stored")
	}
	j := e.st.joins[len(e.st.joins)-1]
	return j.Scopes, j.TokenExpiresAt, j.ExpiresAt, j.MaxTunnels
}

// A3: a bearer token never hands out admin:* scopes, not even ones it holds; only the socket does.
func TestJoinBearerCannotGrantAdminScopes(t *testing.T) {
	e := joinEnv(t, map[string][]string{"tok": {auth.ScopeAdminTokens, auth.ScopeAdminRead}})
	h := e.api.BearerHandler()
	for _, sc := range []string{auth.ScopeAdminTokens, auth.ScopeAdminRead} {
		st, body := e.post(h, "/join", "ph_tok_secret", `{"client_name":"a","scopes":["`+sc+`"]}`)
		if st != http.StatusForbidden {
			t.Errorf("grant %s: %d %s, want 403", sc, st, body)
		}
	}
	if st, body := e.post(e.api.SocketHandler(), "/join", "", `{"client_name":"b","scopes":["admin:tokens","admin:read"]}`); st != http.StatusOK {
		t.Errorf("the socket may grant admin scopes: %d %s", st, body)
	}
}

// A3: the minted token and the link cannot outlive the creator's own token.
func TestJoinCappedByCreatorExpiry(t *testing.T) {
	e := joinEnv(t, map[string][]string{"tok": {auth.ScopeAdminTokens}, "perm": {auth.ScopeAdminTokens}})
	exp := secNow.Add(2 * time.Hour)
	e.st.tokens["tok"].ExpiresAt = &exp
	h := e.api.BearerHandler()

	for _, body := range []string{
		`{"client_name":"a"}`,
		`{"client_name":"a","token_expires_in":"0"}`,
		`{"client_name":"a","token_expires_in":"30d"}`,
		`{"client_name":"a","ttl":"6h","token_expires_in":"30d"}`,
	} {
		st, resp := e.post(h, "/join", "ph_tok_secret", body)
		if st != http.StatusOK {
			t.Fatalf("%s: %d %s", body, st, resp)
		}
		_, tokExp, linkExp, _ := lastJoin(t, e)
		if tokExp == nil || tokExp.After(exp) {
			t.Errorf("%s: token expires %v, must not be later than the creator's %v", body, tokExp, exp)
		}
		if linkExp.After(exp) {
			t.Errorf("%s: link expires %v, after the creator's %v", body, linkExp, exp)
		}
	}
	// A creator without expiry may mint tokens without expiry.
	if st, resp := e.post(h, "/join", "ph_perm_secret", `{"client_name":"b"}`); st != http.StatusOK {
		t.Fatalf("%d %s", st, resp)
	}
	if _, tokExp, _, _ := lastJoin(t, e); tokExp != nil {
		t.Errorf("permanent creator: token expiry %v, want none", tokExp)
	}
	// A creator that is about to expire cannot make a link at all.
	soon := secNow.Add(time.Minute)
	e.st.tokens["tok"].ExpiresAt = &soon
	if st, resp := e.post(h, "/join", "ph_tok_secret", `{"client_name":"c"}`); st != http.StatusForbidden {
		t.Errorf("creator expiring in 1m: %d %s, want 403", st, resp)
	}
}

// A3/A4: max_tunnels of a link made by a bearer token cannot exceed the server limit.
func TestJoinMaxTunnelsCapped(t *testing.T) {
	e := joinEnv(t, map[string][]string{"tok": {auth.ScopeAdminTokens}})
	e.api.maxTunnels = 10
	h := e.api.BearerHandler()
	if st, resp := e.post(h, "/join", "ph_tok_secret", `{"client_name":"a","max_tunnels":100000}`); st != http.StatusBadRequest {
		t.Errorf("max_tunnels over the limit: %d %s, want 400", st, resp)
	}
	if st, resp := e.post(h, "/join", "ph_tok_secret", `{"client_name":"a","max_tunnels":10}`); st != http.StatusOK {
		t.Errorf("max_tunnels at the limit: %d %s", st, resp)
	}
	if st, resp := e.post(e.api.SocketHandler(), "/join", "", `{"client_name":"b","max_tunnels":100}`); st != http.StatusOK {
		t.Errorf("the socket may exceed the limit: %d %s", st, resp)
	}
}

// A4: connect:<client> only if the creator holds it, or is that client.
func TestJoinConnectScopeNeedsCreatorRight(t *testing.T) {
	e := joinEnv(t, map[string][]string{
		"tok":  {auth.ScopeAdminTokens},
		"both": {auth.ScopeAdminTokens, "connect:prod-db"},
	})
	e.st.tokens["tok"].Name = "laptop"
	h := e.api.BearerHandler()
	if st, resp := e.post(h, "/join", "ph_tok_secret", `{"client_name":"a","scopes":["connect:prod-db"]}`); st != http.StatusForbidden {
		t.Errorf("connect:prod-db without holding it: %d %s, want 403", st, resp)
	}
	if st, resp := e.post(h, "/join", "ph_both_secret", `{"client_name":"a","scopes":["connect:prod-db"]}`); st != http.StatusOK {
		t.Errorf("connect:prod-db held by the creator: %d %s", st, resp)
	}
	if st, resp := e.post(h, "/join", "ph_tok_secret", `{"client_name":"b","scopes":["connect:laptop"]}`); st != http.StatusOK {
		t.Errorf("connect to the creator's own client: %d %s", st, resp)
	}
	scopes, _, _, _ := lastJoin(t, e)
	if !slices.Contains(scopes, "connect:laptop") {
		t.Errorf("scopes = %v", scopes)
	}
}

// A6: revoking through the API closes the live sessions of the token right away.
func TestRevokeTokenClosesSessions(t *testing.T) {
	e := newEnv(t, map[string][]string{"adm": {auth.ScopeAdminTokens}, "victim": {auth.ScopeAdminRead}})
	st, body, _ := e.do(e.api.BearerHandler(), "POST", "/tokens/victim/revoke", "ph_adm_secret")
	if st != http.StatusOK {
		t.Fatalf("%d %s", st, body)
	}
	if !slices.Equal(e.be.revokedTokens, []string{"victim"}) {
		t.Errorf("backend was told about %v, want [victim]", e.be.revokedTokens)
	}
}

// A7: paging through the audit log.
func TestAuditPaging(t *testing.T) {
	e := newEnv(t, map[string][]string{"r": {auth.ScopeAdminRead}})
	for i := range 5 {
		e.st.audit = append(e.st.audit, auditFixture(i))
	}
	st, body, _ := e.do(e.api.BearerHandler(), "GET", "/audit?limit=2&before=4", "ph_r_secret")
	if st != http.StatusOK {
		t.Fatalf("%d %s", st, body)
	}
	if !strings.Contains(body, `"id":3`) || !strings.Contains(body, `"id":2`) || strings.Contains(body, `"id":4`) || strings.Contains(body, `"id":1,`) {
		t.Errorf("page = %s, want ids 3 and 2", body)
	}
	if st, _, _ := e.do(e.api.BearerHandler(), "GET", "/audit?before="+strconv.Itoa(-1), "ph_r_secret"); st != http.StatusBadRequest {
		t.Errorf("negative before: %d, want 400", st)
	}
}
