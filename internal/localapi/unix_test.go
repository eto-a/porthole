// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package localapi

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestIsPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket permissions")
	}
	sock := filepath.Join(shortDir(t), "s.sock")
	ln, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chmod(sock, 0); err != nil {
		t.Fatal(err)
	}

	c := NewClient(sock)
	defer c.Close()
	_, err = c.Status(ctxT(t))
	if err == nil {
		t.Fatal("expected a permission error")
	}
	if !IsPermissionDenied(err) {
		t.Errorf("IsPermissionDenied(%v) = false, want true", err)
	}
	if IsUnavailable(err) {
		t.Errorf("IsUnavailable(%v) = true, want false: a denied socket must not trigger standalone mode", err)
	}
}

func TestIsUnavailableStaleSocket(t *testing.T) {
	sock := filepath.Join(shortDir(t), "s.sock")
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	_ = old.Close()

	c := NewClient(sock)
	defer c.Close()
	_, err = c.Status(ctxT(t))
	if !IsUnavailable(err) {
		t.Errorf("IsUnavailable(%v) = false, want true (connection refused)", err)
	}
}

func TestPeerCredInHandlerContext(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no peer credentials on " + runtime.GOOS)
	}
	sock := filepath.Join(shortDir(t), "s.sock")
	ln, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan Cred, 1)
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
	defer srv.Close()

	c := NewClient(sock)
	defer c.Close()
	// Any request works; the handler is not the API handler.
	_ = c.RemoveTunnel(ctxT(t), "x")
	select {
	case cred := <-got:
		if cred.UID != os.Getuid() {
			t.Errorf("peer UID = %d, want %d", cred.UID, os.Getuid())
		}
		if runtime.GOOS == "linux" {
			if cred.PID != os.Getpid() {
				t.Errorf("peer PID = %d, want %d", cred.PID, os.Getpid())
			}
			if cred.GID != os.Getgid() {
				t.Errorf("peer GID = %d, want %d", cred.GID, os.Getgid())
			}
		}
	case <-time.After(testTimeout):
		t.Fatal("handler not called")
	}
}

func TestNotify(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "n.sock")
	pc, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	read := func() string {
		t.Helper()
		_ = pc.SetReadDeadline(time.Now().Add(testTimeout))
		buf := make([]byte, 128)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf[:n])
	}

	t.Setenv("NOTIFY_SOCKET", sock)
	ok, err := Notify(NotifyReady)
	if err != nil || !ok {
		t.Fatalf("Notify = %v, %v; want true, nil", ok, err)
	}
	if got := read(); got != "READY=1" {
		t.Errorf("datagram = %q, want READY=1", got)
	}

	if ok, err := Notify("STATUS=hello\nWATCHDOG=1"); err != nil || !ok {
		t.Fatalf("Notify multi-line = %v, %v", ok, err)
	}
	if got := read(); got != "STATUS=hello\nWATCHDOG=1" {
		t.Errorf("datagram = %q", got)
	}
}

func TestNotifyAbstract(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract sockets are Linux only")
	}
	name := "porthole-notify-test-" + filepath.Base(shortDir(t))
	pc, err := net.ListenPacket("unixgram", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	t.Setenv("NOTIFY_SOCKET", "@"+name)
	if ok, err := Notify(NotifyStopping); err != nil || !ok {
		t.Fatalf("Notify = %v, %v", ok, err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(testTimeout))
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "STOPPING=1" {
		t.Errorf("read %q, %v", buf[:n], err)
	}
}

func TestNotifyErrors(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "relative/path")
	if ok, err := Notify(NotifyReady); ok || err == nil {
		t.Errorf("relative NOTIFY_SOCKET: %v, %v; want false and an error", ok, err)
	}
	t.Setenv("NOTIFY_SOCKET", filepath.Join(shortDir(t), "missing.sock"))
	if ok, err := Notify(NotifyReady); ok || err == nil {
		t.Errorf("missing socket: %v, %v; want false and an error", ok, err)
	}
}
