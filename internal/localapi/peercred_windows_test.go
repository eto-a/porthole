// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localapi

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// tokenIsAdmin must agree with CheckTokenMembership, which is what "is this process an administrator" means for the
// operating system (a UAC-filtered token is not).
func TestTokenIsAdminMatchesCheckTokenMembership(t *testing.T) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	var imp windows.Token
	if err := windows.DuplicateTokenEx(tok, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &imp); err != nil {
		t.Fatal(err)
	}
	defer imp.Close()
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	want, err := imp.IsMember(adminSID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tokenIsAdmin(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("tokenIsAdmin = %v, CheckTokenMembership = %v", got, want)
	}
	t.Logf("this test process is an administrator: %v", got)
}

func TestBuildPipeCredFailsClosed(t *testing.T) {
	boom := errors.New("access denied")
	ok := func() (*windows.SID, bool, error) {
		sid, _ := windows.StringToSid("S-1-5-21-1-2-3-1001")
		return sid, true, nil
	}
	fail := func() (*windows.SID, bool, error) { return nil, false, boom }

	// The PID could not be read: a pipe peer without an identity, not "no credentials" (which would mean trusted).
	c, isCred := buildPipeCred(0, boom, ok)
	if !isCred || c.UID != -1 || c.SID != "" || c.Admin {
		t.Errorf("no PID: %+v, %v", c, isCred)
	}
	// The token could not be read: no SID and not an administrator.
	c, isCred = buildPipeCred(42, nil, fail)
	if !isCred || c.PID != 42 || c.SID != "" || c.Admin {
		t.Errorf("no token: %+v, %v", c, isCred)
	}
	c, isCred = buildPipeCred(42, nil, ok)
	if !isCred || c.SID != "S-1-5-21-1-2-3-1001" || !c.Admin || c.Principal() != c.SID {
		t.Errorf("ok: %+v, %v", c, isCred)
	}
}

// A pipe client is identified by the token the pipe reports (impersonation), not by a lookup of its PID: a client from
// this process is the current user, and is an administrator iff this process is elevated.
func TestPipeClientIdentityIsTheClientToken(t *testing.T) {
	name := pipeName(t)
	ln, err := Listen(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := serveCreds(t, ln)

	c := NewClient(name)
	defer c.Close()
	_ = c.RemoveTunnel(ctxT(t), "x")
	select {
	case cred := <-got:
		if want := CurrentSID(); want == "" || cred.SID != want {
			t.Errorf("peer SID = %q, want %q", cred.SID, want)
		}
		if want := windows.GetCurrentProcessToken().IsElevated(); cred.Admin != want {
			t.Errorf("peer Admin = %v, want %v (this process elevated)", cred.Admin, want)
		}
	case <-time.After(testTimeout):
		t.Fatal("handler not called")
	}
}
