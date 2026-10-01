// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func pipeName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`%sporthole-test-%d-%d`, pipePrefix, os.Getpid(), time.Now().UnixNano())
}

func mySID(t *testing.T) string {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return sid.String()
}

// serveCreds serves a handler that reports the peer credentials of every request on ln.
func serveCreds(t *testing.T, ln net.Listener) <-chan Cred {
	t.Helper()
	got := make(chan Cred, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cred, ok := PeerCredFromContext(r.Context())
		if !ok {
			cred = Cred{UID: -2}
		}
		got <- cred
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Config.ConnContext = ConnContext
	srv.Start()
	t.Cleanup(srv.Close)
	return got
}

func TestPipeUserRoundTripAndPeerIdentity(t *testing.T) {
	name := pipeName(t)
	ln, err := Listen(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := serveCreds(t, ln)

	c := NewClient(name)
	defer c.Close()
	// Any request works; the handler is not the API handler.
	_ = c.RemoveTunnel(ctxT(t), "x")
	select {
	case cred := <-got:
		if cred.PID != os.Getpid() {
			t.Errorf("peer PID = %d, want %d", cred.PID, os.Getpid())
		}
		if want := mySID(t); cred.SID != want {
			t.Errorf("peer SID = %q, want %q", cred.SID, want)
		}
		if cred.UID != -1 || cred.GID != -1 {
			t.Errorf("peer UID/GID = %d/%d, want -1/-1 on Windows", cred.UID, cred.GID)
		}
		if u, err := user.Current(); err == nil && !strings.EqualFold(cred.User, u.Username) {
			t.Errorf("peer User = %q, want %q", cred.User, u.Username)
		}
		attrs := fmt.Sprint(peerAttrs(WithPeerCred(t.Context(), cred)))
		if !strings.Contains(attrs, "peer_sid") || !strings.Contains(attrs, "peer_user") || strings.Contains(attrs, "peer_uid") {
			t.Errorf("peerAttrs = %s", attrs)
		}
	case <-time.After(testTimeout):
		t.Fatal("handler not called")
	}
}

func TestPipeAlreadyRunning(t *testing.T) {
	name := pipeName(t)
	ln, err := Listen(name, 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	defer func() { _ = ln.Close() }()

	ln2, err := Listen(name, 0)
	if !errors.Is(err, ErrAlreadyRunning) {
		if ln2 != nil {
			_ = ln2.Close()
		}
		t.Fatalf("second Listen = %v, want ErrAlreadyRunning", err)
	}
}

func TestPipeUnavailable(t *testing.T) {
	c := NewClient(pipeName(t))
	defer c.Close()
	_, err := c.Status(ctxT(t))
	if err == nil {
		t.Fatal("expected an error for a pipe nobody listens on")
	}
	if !IsUnavailable(err) {
		t.Errorf("IsUnavailable(%v) = false, want true", err)
	}
}

func TestPipeForeignDACLRefused(t *testing.T) {
	name := pipeName(t)
	// A squatter (or a careless daemon) that lets everybody in: the client must not talk to it.
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;WD)"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { // keep an instance waiting so that the dial gets as far as the check
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	c, err := Dial(ctxT(t), name)
	if err == nil {
		_ = c.Close()
		t.Fatal("Dial to a pipe open to Everyone succeeded")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("error %q does not say that the pipe was refused", err)
	}
}

func TestPipeSystemSDDL(t *testing.T) {
	const want = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;S-1-5-32-545)(A;;0x12019b;;;S-1-1-0)"
	if got := systemSDDL([]string{"S-1-5-32-545", "S-1-1-0"}); got != want {
		t.Errorf("systemSDDL = %s, want %s", got, want)
	}
	if got := systemSDDL(nil); got != "D:P(A;;GA;;;SY)(A;;GA;;;BA)" {
		t.Errorf("systemSDDL(nil) = %s", got)
	}
	// The access of an allowed principal is read/write without FILE_CREATE_PIPE_INSTANCE (FILE_APPEND_DATA).
	if pipeClientAccess&windows.FILE_APPEND_DATA != 0 || pipeClientAccess&windows.FILE_GENERIC_READ != windows.FILE_GENERIC_READ {
		t.Errorf("pipeClientAccess = %#x", uint32(pipeClientAccess))
	}
	for _, sddl := range []string{want, userSDDL(mySID(t))} {
		if _, err := winio.SddlToSecurityDescriptor(sddl); err != nil {
			t.Errorf("SDDL %q does not parse: %v", sddl, err)
		}
	}
}

func TestListenAllowOnlyForProtectedPipes(t *testing.T) {
	ln, err := ListenAllow(pipeName(t), 0, []string{"S-1-1-0"})
	if err == nil {
		_ = ln.Close()
		t.Fatal("ListenAllow with an allow list on an unprotected pipe succeeded")
	}
	if !strings.Contains(err.Error(), "allow") {
		t.Errorf("error %q does not mention allow", err)
	}
}

func TestResolveAllow(t *testing.T) {
	me := mySID(t)
	got, err := resolveAllow([]string{"S-1-1-0", me})
	if err != nil || len(got) != 2 || got[0] != "S-1-1-0" || got[1] != me {
		t.Errorf("resolveAllow(SIDs) = %v, %v", got, err)
	}
	if u, err := user.Current(); err == nil {
		got, err := resolveAllow([]string{u.Username})
		if err != nil || len(got) != 1 || got[0] != me {
			t.Errorf("resolveAllow(%q) = %v, %v; want [%s]", u.Username, got, err, me)
		}
	}
	for _, bad := range []string{"", "S-1-bogus", "no such account \\ xyz"} {
		if _, err := resolveAllow([]string{bad}); err == nil {
			t.Errorf("resolveAllow(%q) succeeded", bad)
		}
	}
}

func TestSystemPipeNeedsAdministrator(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("running elevated: see TestSystemPipeElevated")
	}
	ln, err := Listen(protectedPrefix+fmt.Sprintf("porthole-test-%d", os.Getpid()), 0)
	if err == nil {
		_ = ln.Close()
		t.Fatal("creating a pipe under ProtectedPrefix\\Administrators succeeded without elevation")
	}
	if !strings.Contains(err.Error(), "administrator") {
		t.Errorf("error %q does not hint at administrator rights", err)
	}
}

// TestSystemPipeElevated runs only in an elevated shell with PORTHOLE_TEST_SYSTEM_PIPE=1: it creates a pipe under
// ProtectedPrefix\Administrators and talks to it through the client.
func TestSystemPipeElevated(t *testing.T) {
	if os.Getenv("PORTHOLE_TEST_SYSTEM_PIPE") != "1" || !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("set PORTHOLE_TEST_SYSTEM_PIPE=1 in an elevated shell")
	}
	name := protectedPrefix + fmt.Sprintf("porthole-test-%d", os.Getpid())
	ln, err := ListenAllow(name, 0, []string{mySID(t)})
	if err != nil {
		t.Fatal(err)
	}
	got := serveCreds(t, ln)
	c := NewClient(name)
	defer c.Close()
	_ = c.RemoveTunnel(ctxT(t), "x")
	select {
	case cred := <-got:
		if cred.PID != os.Getpid() || cred.SID != mySID(t) {
			t.Errorf("peer = %+v", cred)
		}
	case <-time.After(testTimeout):
		t.Fatal("handler not called")
	}
}

func TestWindowsEndpointPaths(t *testing.T) {
	user := UserSocketPath()
	if want := pipePrefix + "porthole-" + mySID(t); user != want {
		t.Errorf("UserSocketPath = %q, want %q", user, want)
	}
	if SystemSocketPath != `\\.\pipe\ProtectedPrefix\Administrators\porthole` {
		t.Errorf("SystemSocketPath = %q", SystemSocketPath)
	}
	if paths := DefaultSocketPaths(); len(paths) != 2 || paths[0] != user || paths[1] != SystemSocketPath {
		t.Errorf("DefaultSocketPaths = %v", paths)
	}
}
