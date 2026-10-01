// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/transport"
)

// joinHarness is a server over a real SQLite store: redemption is a database transaction, a fake would prove little.
type joinHarness struct {
	*harness
	sq *store.SQLite
}

func newJoinHarness(t *testing.T) *joinHarness {
	t.Helper()
	sq, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "porthole.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sq.Close() })
	h := newHarness(t, func(_ *config.Config, o *Options) { o.Store = sq })
	return &joinHarness{harness: h, sq: sq}
}

// code stores a join code created now and returns its string form.
func (h *joinHarness) code(name string, mut ...func(*store.JoinCode)) (id, code string) {
	h.t.Helper()
	g, err := auth.Generate()
	if err != nil {
		h.t.Fatal(err)
	}
	now := h.clock.Now()
	jc := &store.JoinCode{
		ID: g.ID, CodeHash: g.Hash(), ClientName: name, Scopes: append([]string(nil), auth.DefaultScopes...),
		RemoteControl: true, CreatedAt: now, ExpiresAt: now.Add(store.DefaultJoinTTL), CreatedBy: "socket",
	}
	for _, m := range mut {
		m(jc)
	}
	if err := h.sq.CreateJoinCode(context.Background(), jc); err != nil {
		h.t.Fatal(err)
	}
	return g.ID, g.JoinString()
}

// join posts a code to the join endpoint of the control host.
func (h *joinHarness) join(code string) (int, http.Header, string) {
	h.t.Helper()
	body, _ := json.Marshal(proto.JoinRequest{Code: code})
	req, err := http.NewRequest(http.MethodPost, h.web.URL+proto.JoinPath, strings.NewReader(string(body)))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Host = testDomain
	resp, err := h.httpc.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func errCodeOf(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("not an error document: %q", body)
	}
	return e.Error.Code
}

func (h *joinHarness) audit() []store.AuditEntry {
	h.t.Helper()
	es, err := h.sq.ListAudit(context.Background(), 100)
	if err != nil {
		h.t.Fatal(err)
	}
	return es
}

func TestJoinRedeemGivesWorkingToken(t *testing.T) {
	h := newJoinHarness(t)
	id, code := h.code("laptop")

	st, hdr, body := h.join(code)
	if st != http.StatusOK {
		t.Fatalf("redeem: %d %s", st, body)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", hdr.Get("Cache-Control"))
	}
	var res proto.JoinResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.ClientName != "laptop" || res.ServerURL != "https://"+testDomain {
		t.Errorf("response = %+v", res)
	}

	// The permanent token passes the handshake as the client the link was made for.
	c := loginAt(t, h.wsURL, res.Token, transport.DialOptions{})
	if c.ok.ClientName != "laptop" {
		t.Errorf("logged in as %q, want laptop", c.ok.ClientName)
	}

	audit := h.audit()
	if len(audit) != 1 || audit[0].Action != "join.redeem" || audit[0].Actor != id || audit[0].Target != "laptop" || audit[0].Result != "ok" {
		t.Fatalf("audit = %+v", audit)
	}
	if strings.Contains(audit[0].Args, code) || strings.Contains(audit[0].Args, res.Token) {
		t.Errorf("audit args hold a secret: %s", audit[0].Args)
	}
}

func TestJoinRedeemTwiceFails(t *testing.T) {
	h := newJoinHarness(t)
	id, code := h.code("laptop")
	if st, _, body := h.join(code); st != http.StatusOK {
		t.Fatalf("first: %d %s", st, body)
	}
	st, _, body := h.join(code)
	if st != http.StatusGone || errCodeOf(t, body) != proto.CodeJoinUsed {
		t.Errorf("second: %d %s, want 410 %s", st, body, proto.CodeJoinUsed)
	}
	audit := h.audit() // newest first
	if len(audit) != 2 || audit[0].Result != "error: "+proto.CodeJoinUsed || audit[0].Actor != id {
		t.Errorf("audit = %+v", audit)
	}
}

func TestJoinExpiredAndRevoked(t *testing.T) {
	h := newJoinHarness(t)
	_, expired := h.code("old")
	revokedID, revoked := h.code("gone")
	if err := h.sq.RevokeJoinCode(context.Background(), revokedID, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(store.DefaultJoinTTL + time.Second)

	if st, _, body := h.join(expired); st != http.StatusGone || errCodeOf(t, body) != proto.CodeJoinExpired {
		t.Errorf("expired: %d %s", st, body)
	}
	if st, _, body := h.join(revoked); st != http.StatusGone || errCodeOf(t, body) != proto.CodeJoinRevoked {
		t.Errorf("revoked: %d %s", st, body)
	}
}

func TestJoinBadInput(t *testing.T) {
	h := newJoinHarness(t)
	g, _ := auth.Generate()
	other, _ := auth.Generate()
	_, code := h.code("laptop")
	wrongSecret := auth.JoinPrefix + strings.Split(code, "_")[1] + "_" + other.Secret

	for name, c := range map[string]string{"empty": "", "token not code": g.String(), "unknown id": g.JoinString(), "wrong secret": wrongSecret} {
		st, _, body := h.join(c)
		want := proto.CodeInvalidJoinCode
		if st != http.StatusBadRequest && st != http.StatusNotFound || errCodeOf(t, body) != want {
			t.Errorf("%s: %d %s, want 4xx %s", name, st, body, want)
		}
	}
	if len(h.audit()) != 0 {
		t.Errorf("guesses reached the audit log: %+v", h.audit())
	}
	// The wrong guesses spent nothing.
	if st, _, body := h.join(code); st != http.StatusOK {
		t.Errorf("real code after bad guesses: %d %s", st, body)
	}
}

func TestJoinMethodAndTokenName(t *testing.T) {
	h := newJoinHarness(t)
	req, _ := http.NewRequest(http.MethodGet, h.web.URL+proto.JoinPath, nil)
	req.Host = testDomain
	resp, err := h.httpc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET join: %d, want 405", resp.StatusCode)
	}

	// The name is held by an active token: the code is refused and stays usable.
	_, code := h.code("dup2")
	if err := h.sq.CreateToken(context.Background(), &store.Token{ID: "bbbbbbbbbbbb", Name: "dup2", SecretHash: []byte{1}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if st, _, body := h.join(code); st != http.StatusConflict || errCodeOf(t, body) != proto.CodeNameTaken {
		t.Errorf("name taken: %d %s, want 409", st, body)
	}
}

func TestJoinRateLimited(t *testing.T) {
	h := newJoinHarness(t)
	_, code := h.code("laptop")
	g, _ := auth.Generate()
	for range failBurst {
		if st, _, _ := h.join(g.JoinString()); st == http.StatusTooManyRequests {
			t.Fatal("limited before the burst was used up")
		}
	}
	st, hdr, body := h.join(code) // even a valid code is refused while the address is blocked
	if st != http.StatusTooManyRequests || errCodeOf(t, body) != proto.CodeRateLimited || hdr.Get("Retry-After") == "" {
		t.Fatalf("after the burst: %d %v %s, want 429 with Retry-After", st, hdr, body)
	}
	// The block lifts as the budget refills (5 per minute).
	h.clock.advance(2 * time.Minute)
	if st, _, body := h.join(code); st != http.StatusOK {
		t.Errorf("after waiting: %d %s", st, body)
	}
}

func TestJoinPageDoesNotRedeem(t *testing.T) {
	h := newJoinHarness(t)
	_, code := h.code("laptop")
	reply, body := h.get(testDomain, "/j/"+code, nil)
	if reply.StatusCode != http.StatusOK || !strings.HasPrefix(reply.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("page: %d %v", reply.StatusCode, reply.Header)
	}
	if !strings.Contains(body, "porthole join https://"+testDomain+"/j/"+code) {
		t.Errorf("page does not show the command: %q", body)
	}
	if reply.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", reply.Header.Get("Cache-Control"))
	}
	// Fetching the page twice, as a link preview would, leaves the code usable.
	h.get(testDomain, "/j/"+code, nil)
	if st, _, b := h.join(code); st != http.StatusOK {
		t.Errorf("redeem after page views: %d %s", st, b)
	}
	if reply, _ := h.get(testDomain, "/j/not-a-code", nil); reply.StatusCode != http.StatusNotFound {
		t.Errorf("malformed code page: %d, want 404", reply.StatusCode)
	}
	// On a tunnel host the path belongs to the tunnelled application, not to the join page.
	if reply, _ := h.get("app."+testDomain, "/j/"+code, nil); reply.StatusCode == http.StatusOK {
		t.Error("join page served on a tunnel host")
	}
}
