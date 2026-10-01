// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

// fakeAPI is an apiClient with scripted answers.
type fakeAPI struct {
	mu sync.Mutex

	statusErr error // what the probe (Status) returns; nil means a live daemon
	status    localapi.Status
	tunnels   []localapi.Tunnel

	addResult localapi.Tunnel
	addErr    error
	gotAdd    []localapi.AddTunnelRequest
	removeErr error
	removed   []string

	reloadRes localapi.ReloadResult
	reloadErr error

	attachEvents []localapi.Event // played after the attached event, then Attach waits for ctx
	attachErr    error            // returned at once instead of attaching
	endStream    bool             // return nil after the events instead of waiting for ctx
	gotAttach    []localapi.AddTunnelRequest
	played       chan struct{} // closed once the events were played
	closed       int
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		status: localapi.Status{
			Version: "9.9", PID: 4242, StartedAt: time.Now().Add(-90 * time.Second), Server: "https://tun.example.com",
			State: localapi.StateConnected, ClientName: "home", TunnelsFile: "/etc/porthole/tunnels.yaml",
		},
		played: make(chan struct{}),
	}
}

func (f *fakeAPI) Status(context.Context) (localapi.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return localapi.Status{}, f.statusErr
	}
	st := f.status
	st.Tunnels = f.tunnels
	return st, nil
}

func (f *fakeAPI) Tunnels(context.Context) ([]localapi.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tunnels, nil
}

func (f *fakeAPI) AddTunnel(_ context.Context, req localapi.AddTunnelRequest) (localapi.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotAdd = append(f.gotAdd, req)
	return f.addResult, f.addErr
}

func (f *fakeAPI) RemoveTunnel(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, name)
	return f.removeErr
}

func (f *fakeAPI) Reload(context.Context) (localapi.ReloadResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloadRes, f.reloadErr
}

func (f *fakeAPI) Attach(ctx context.Context, req localapi.AddTunnelRequest, fn func(localapi.Event) error) error {
	f.mu.Lock()
	f.gotAttach = append(f.gotAttach, req)
	events, attachErr, end := f.attachEvents, f.attachErr, f.endStream
	f.mu.Unlock()
	if attachErr != nil {
		return attachErr
	}
	for i := range events {
		if err := fn(events[i]); err != nil {
			if errors.Is(err, localapi.ErrStopStream) {
				return nil
			}
			return err
		}
	}
	close(f.played)
	if end {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeAPI) Close() {
	f.mu.Lock()
	f.closed++
	f.mu.Unlock()
}

// lockedBuffer is a bytes.Buffer that can be read while a command still writes to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// withSockets makes the deps look for daemons at the given paths, answered by the given fakes (a path without a
// fake is dialled as an unavailable socket). It returns the list of dialled paths.
func withSockets(d deps, fakes map[string]*fakeAPI, order ...string) (deps, *[]string) {
	var dialled []string
	d.socketPaths = func() []string { return order }
	d.dial = func(p string) apiClient {
		dialled = append(dialled, p)
		if f, ok := fakes[p]; ok {
			return f
		}
		g := newFakeAPI()
		g.statusErr = fmt.Errorf("localapi: GET /v1/status: %w", os.ErrNotExist)
		return g
	}
	return d, &dialled
}

var errPerm = fmt.Errorf("localapi: GET /v1/status: dial unix /run/porthole/porthole.sock: %w", fs.ErrPermission)

// executeCtx is execute with a caller-supplied context (to play Ctrl-C).
func executeCtx(ctx context.Context, d deps, args ...string) (stdout, stderr *lockedBuffer, err error) {
	root := newRoot("1.2.3", d)
	stdout, stderr = &lockedBuffer{}, &lockedBuffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	err = root.ExecuteContext(ctx)
	return stdout, stderr, err
}

func readyEvents(name, local, url string) []localapi.Event {
	tun := localapi.Tunnel{Name: name, LocalAddr: local, State: localapi.TunnelPending, Lifetime: localapi.LifetimeAttached}
	return []localapi.Event{
		{Type: localapi.EventAttached, Name: name, Tunnel: &tun},
		{Type: localapi.EventConnected, ClientName: "home"},
		{Type: localapi.EventTunnelReady, Name: name, PublicURL: url},
	}
}

// runAttached runs args against a daemon fake, cancels the command (Ctrl-C) once the events were played, and
// returns the output.
func runAttached(t *testing.T, d deps, f *fakeAPI, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-f.played:
			time.Sleep(20 * time.Millisecond)
			cancel()
		case <-time.After(5 * time.Second):
			cancel()
		}
	}()
	so, se, err := executeCtx(ctx, d, args...)
	return so.String(), se.String(), err
}

func TestHTTPAttachesToTheDaemon(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	f := newFakeAPI()
	f.attachEvents = readyEvents("blog", "127.0.0.1:8080", "https://blog-home.tun.example.com")
	ran := false
	d, dialled := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	d.run = func(context.Context, client.Options) error { ran = true; return nil }

	stdout, stderr, err := runAttached(t, d, f, "--config", path, "http", "8080", "--name", "blog")
	if err != nil {
		t.Fatalf("err = %v, stderr %q", err, stderr)
	}
	if ran {
		t.Error("the tunnel ran in-process although a daemon was reachable")
	}
	if len(f.gotAttach) != 1 || f.gotAttach[0].Type != "http" || f.gotAttach[0].Addr != "127.0.0.1:8080" || f.gotAttach[0].Name != "blog" {
		t.Errorf("attach request %+v", f.gotAttach)
	}
	if want := "connected as home\nhttps://blog-home.tun.example.com -> 127.0.0.1:8080\n"; stdout != want {
		t.Errorf("stdout %q, want %q", stdout, want)
	}
	if f.closed == 0 {
		t.Error("the client was not closed")
	}
	if len(*dialled) != 1 {
		t.Errorf("dialled %v", *dialled)
	}
}

func TestSSHAndTCPAttach(t *testing.T) {
	f := newFakeAPI()
	f.attachEvents = readyEvents("ssh", "127.0.0.1:22", "tcp://tun.example.com:20018")
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")

	stdout, _, err := runAttached(t, d, f, "ssh", "--user", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "tcp://tun.example.com:20018 -> 127.0.0.1:22\n  ssh -p 20018 bob@tun.example.com\n") {
		t.Errorf("stdout %q", stdout)
	}
	if got := f.gotAttach[0]; got.Type != "ssh" || got.Name != "ssh" || got.Addr != "127.0.0.1:22" {
		t.Errorf("attach request %+v", got)
	}

	f2 := newFakeAPI()
	f2.attachEvents = readyEvents("tcp-5432", "127.0.0.1:5432", "tcp://tun.example.com:20017")
	d, _ = withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f2}, "/s/user")
	stdout, _, err = runAttached(t, d, f2, "tcp", "5432", "--remote-port", "20017")
	if err != nil || strings.Contains(stdout, "ssh -p") {
		t.Fatalf("stdout %q, err %v", stdout, err)
	}
	if got := f2.gotAttach[0]; got.Type != "tcp" || got.RemotePort != 20017 || got.Addr != "127.0.0.1:5432" {
		t.Errorf("attach request %+v", got)
	}
}

func TestNoDaemonRunsInProcess(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var got client.Options
	d, dialled := withSockets(capture(testDeps(nil), &got), nil, "/s/user", "/s/system")

	if _, _, err := execute(t, d, "--config", path, "http", "8080"); err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 1 || got.ServerURL != "https://tun.example.com" {
		t.Fatalf("the tunnel did not run in-process: %+v", got)
	}
	if want := []string{"/s/user", "/s/system"}; !equalStrings(*dialled, want) {
		t.Errorf("looked at %v, want %v in this order", *dialled, want)
	}
}

func equalStrings(a, b []string) bool { return slices.Equal(a, b) }

func TestRealUnavailableSocketMeansNoDaemon(t *testing.T) {
	// Real localapi client, a socket path that does not exist: this must read as "no daemon" on every OS.
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	var got client.Options
	d := capture(testDeps(nil), &got)
	d.socketPaths = func() []string { return []string{filepath.Join(dir, "missing.sock")} }
	d.dial = func(p string) apiClient { return localapi.NewClient(p) }
	if _, _, err := execute(t, d, "--config", path, "http", "8080"); err != nil || len(got.Tunnels) != 1 {
		t.Fatalf("err = %v, options %+v", err, got)
	}
}

func TestPermissionDeniedNeverFallsBack(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	denied := newFakeAPI()
	denied.statusErr = errPerm
	ran := false
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/run/porthole/porthole.sock": denied}, "/s/user", "/run/porthole/porthole.sock")
	d.run = func(context.Context, client.Options) error { ran = true; return nil }

	_, _, err := execute(t, d, "--config", path, "http", "8080")
	if err == nil || ran {
		t.Fatalf("err = %v, ran = %v: access denied must not fall back to an in-process client", err, ran)
	}
	for _, want := range []string{"porthole-client", "--no-daemon", "/run/porthole/porthole.sock"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if !localapi.IsPermissionDenied(err) {
		t.Error("the original permission error is not reachable")
	}

	// --no-daemon is the way out.
	if _, _, err := execute(t, d, "--config", path, "http", "8080", "--no-daemon"); err != nil || !ran {
		t.Errorf("--no-daemon: err = %v, ran = %v", err, ran)
	}
}

func TestLaterSocketWinsOverDeniedOne(t *testing.T) {
	denied := newFakeAPI()
	denied.statusErr = errPerm
	f := newFakeAPI()
	f.attachEvents = readyEvents("http-80", "127.0.0.1:80", "https://x.example.com")
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": denied, "/s/system": f}, "/s/user", "/s/system")
	if _, _, err := runAttached(t, d, f, "http", "80"); err != nil {
		t.Fatal(err)
	}
	if len(f.gotAttach) != 1 {
		t.Error("the reachable daemon was not used")
	}
}

func TestSocketSelection(t *testing.T) {
	f := newFakeAPI()
	f.attachEvents = readyEvents("http-80", "127.0.0.1:80", "https://x.example.com")
	env := map[string]string{envSocket: "/s/env"}

	// --socket is exclusive and wins.
	d, dialled := withSockets(testDeps(env), map[string]*fakeAPI{"/s/flag": f}, "/s/user")
	if _, _, err := runAttached(t, d, f, "--socket", "/s/flag", "http", "80"); err != nil || !equalStrings(*dialled, []string{"/s/flag"}) {
		t.Fatalf("err = %v, dialled %v", err, *dialled)
	}

	// $PORTHOLE_SOCKET comes before the default locations.
	f = newFakeAPI()
	f.attachEvents = readyEvents("http-80", "127.0.0.1:80", "https://x.example.com")
	d, dialled = withSockets(testDeps(env), map[string]*fakeAPI{"/s/env": f}, "/s/user", "/s/env")
	if _, _, err := runAttached(t, d, f, "http", "80"); err != nil || !equalStrings(*dialled, []string{"/s/env"}) {
		t.Fatalf("err = %v, dialled %v", err, *dialled)
	}

	// An explicit --socket that nobody answers on is an error, not a reason to run standalone; the environment is not.
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	ran := false
	d, _ = withSockets(testDeps(env), nil, "/s/user")
	d.run = func(context.Context, client.Options) error { ran = true; return nil }
	if _, _, err := execute(t, d, "--config", path, "--socket", "/s/gone", "http", "80"); err == nil || ran ||
		!strings.Contains(err.Error(), "/s/gone") {
		t.Errorf("explicit missing socket: err = %v, ran = %v", err, ran)
	}
	if _, _, err := execute(t, d, "--config", path, "http", "80"); err != nil || !ran {
		t.Errorf("missing socket from the environment: err = %v, ran = %v", err, ran)
	}
}

func TestDaemonFlagRequiresADaemon(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	ran := false
	d, _ := withSockets(testDeps(nil), nil, "/s/user")
	d.run = func(context.Context, client.Options) error { ran = true; return nil }
	_, _, err := execute(t, d, "--config", path, "http", "80", "--daemon")
	if err == nil || ran || !strings.Contains(err.Error(), "no porthole daemon") {
		t.Fatalf("err = %v, ran = %v", err, ran)
	}
	if _, _, err := execute(t, d, "--config", path, "http", "80", "--daemon", "--no-daemon"); err == nil {
		t.Error("--daemon and --no-daemon must exclude each other")
	}
	if _, _, err := execute(t, d, "--config", path, "http", "80", "--detach", "--no-daemon"); err == nil {
		t.Error("--detach and --no-daemon must exclude each other")
	}
	if _, _, err := execute(t, d, "--config", path, "http", "80", "--detach"); err == nil || ran {
		t.Errorf("--detach without a daemon: err = %v, ran = %v", err, ran)
	}
}

func TestCredentialFlagsConflictWithADaemon(t *testing.T) {
	path := writeConfig(t, "https://tun.example.com", testToken(t))
	f := newFakeAPI()
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	for _, flags := range [][]string{
		{"--token", testToken(t)},
		{"--server", "https://other.example.com"},
		{"--max-initial-attempts", "2"},
	} {
		args := append([]string{"--config", path, "http", "80"}, flags...)
		_, _, err := execute(t, d, args...)
		if err == nil || !strings.Contains(err.Error(), flags[0]) || !strings.Contains(err.Error(), "--no-daemon") {
			t.Errorf("%v: err = %v", flags, err)
		}
	}
	if len(f.gotAttach) != 0 {
		t.Error("a tunnel was attached despite the conflicting flags")
	}

	// The same flags are fine without a daemon, and with --no-daemon.
	var got client.Options
	d2, _ := withSockets(capture(testDeps(nil), &got), nil, "/s/user")
	if _, _, err := execute(t, d2, "--config", path, "http", "80", "--token", testToken(t)); err != nil || len(got.Tunnels) != 1 {
		t.Errorf("err = %v, %+v", err, got)
	}
	d3, _ := withSockets(capture(testDeps(nil), &got), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	got = client.Options{}
	if _, _, err := execute(t, d3, "--config", path, "http", "80", "--token", testToken(t), "--no-daemon"); err != nil || len(got.Tunnels) != 1 {
		t.Errorf("--no-daemon: err = %v, %+v", err, got)
	}
}

func TestAttachReportsARefusedRegistration(t *testing.T) {
	f := newFakeAPI()
	tun := localapi.Tunnel{Name: "blog", LocalAddr: "127.0.0.1:80"}
	f.attachEvents = []localapi.Event{
		{Type: localapi.EventAttached, Name: "blog", Tunnel: &tun},
		{Type: localapi.EventTunnelClosed, Name: "blog", Reason: "name_taken: name blog is taken", Error: "name_taken: name blog is taken"},
	}
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	_, _, err := execute(t, d, "http", "80", "--name", "blog")
	if err == nil || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("err = %v, want the name-taken hint", err)
	}
	var perr *proto.Error
	if !errors.As(err, &perr) || perr.Code != proto.CodeNameTaken {
		t.Errorf("the server error is not reachable: %v", err)
	}
}

func TestAttachSurvivesALaterServerSideClose(t *testing.T) {
	f := newFakeAPI()
	f.attachEvents = append(readyEvents("blog", "127.0.0.1:80", "https://blog.example.com"),
		localapi.Event{Type: localapi.EventTunnelClosed, Name: "blog", Reason: "quota", Error: "quota"},
		localapi.Event{Type: localapi.EventDisconnected, Error: "boom", RetryInMS: 2300},
	)
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	_, stderr, err := runAttached(t, d, f, "http", "80", "--name", "blog")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "tunnel blog closed: quota") || !strings.Contains(stderr, "reconnecting in 3s: boom") {
		t.Errorf("stderr %q", stderr)
	}
}

func TestAttachEndsWhenTheTunnelIsRemovedOnTheDaemon(t *testing.T) {
	f := newFakeAPI()
	f.attachEvents = append(readyEvents("blog", "127.0.0.1:80", "https://blog.example.com"),
		localapi.Event{Type: localapi.EventTunnelClosed, Name: "blog", Reason: "removed"})
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	_, stderr, err := execute(t, d, "http", "80", "--name", "blog")
	if err != nil || !strings.Contains(stderr, "removed on the daemon") {
		t.Fatalf("err = %v, stderr %q", err, stderr)
	}
}

func TestAttachFailsWhenTheDaemonGoesAway(t *testing.T) {
	f := newFakeAPI()
	f.attachEvents = readyEvents("blog", "127.0.0.1:80", "https://blog.example.com")
	f.endStream = true
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	_, _, err := execute(t, d, "http", "80", "--name", "blog")
	if err == nil || !strings.Contains(err.Error(), "closed the connection") {
		t.Fatalf("err = %v", err)
	}
}

func TestAttachAPIErrors(t *testing.T) {
	f := newFakeAPI()
	f.attachErr = localapi.NewError(localapi.CodeNameTaken, "tunnel name %q is defined in tunnels.yaml; pick another name", "blog")
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	_, _, err := execute(t, d, "http", "80", "--name", "blog")
	if err == nil || !strings.Contains(err.Error(), "defined in tunnels.yaml") || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("err = %v", err)
	}
}

func TestDetach(t *testing.T) {
	f := newFakeAPI()
	f.addResult = localapi.Tunnel{Name: "ssh", LocalAddr: "127.0.0.1:22", State: localapi.TunnelPending}
	f.tunnels = []localapi.Tunnel{{Name: "ssh", LocalAddr: "127.0.0.1:22", State: localapi.TunnelReady, PublicURL: "tcp://tun.example.com:20018"}}
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")

	stdout, _, err := execute(t, d, "ssh", "--detach", "--user", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.gotAttach) != 0 || len(f.gotAdd) != 1 || f.gotAdd[0].Type != "ssh" || f.gotAdd[0].Name != "ssh" {
		t.Errorf("attach %+v, add %+v", f.gotAttach, f.gotAdd)
	}
	for _, want := range []string{"tcp://tun.example.com:20018 -> 127.0.0.1:22\n", "ssh -p 20018 bob@tun.example.com", "porthole close ssh"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout %q does not contain %q", stdout, want)
		}
	}
}

func TestDetachFailureRemovesTheTunnel(t *testing.T) {
	f := newFakeAPI()
	f.addResult = localapi.Tunnel{Name: "blog", State: localapi.TunnelPending}
	f.tunnels = []localapi.Tunnel{{Name: "blog", State: localapi.TunnelFailed, Error: "forbidden: not allowed"}}
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	_, _, err := execute(t, d, "http", "80", "--detach", "--name", "blog")
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err = %v", err)
	}
	if !equalStrings(f.removed, []string{"blog"}) {
		t.Errorf("removed %v: a failed detached tunnel must not stay behind", f.removed)
	}
}

func TestDetachTimeout(t *testing.T) {
	f := newFakeAPI()
	f.addResult = localapi.Tunnel{Name: "blog", State: localapi.TunnelPending}
	f.tunnels = []localapi.Tunnel{{Name: "blog", State: localapi.TunnelPending}}
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	d.detachTimeout = 250 * time.Millisecond
	_, _, err := execute(t, d, "http", "80", "--detach", "--name", "blog")
	if err == nil || !strings.Contains(err.Error(), "not ready") || !strings.Contains(err.Error(), "porthole close blog") {
		t.Fatalf("err = %v", err)
	}
	if len(f.removed) != 0 {
		t.Error("a tunnel that is merely pending must stay")
	}
}

func TestDetachAddError(t *testing.T) {
	f := newFakeAPI()
	f.addErr = localapi.NewError(localapi.CodeNameTaken, "tunnel name %q is already in use", "blog")
	d, _ := withSockets(testDeps(nil), map[string]*fakeAPI{"/s/user": f}, "/s/user")
	_, _, err := execute(t, d, "http", "80", "--detach", "--name", "blog")
	if err == nil || !strings.Contains(err.Error(), "already in use") || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("err = %v", err)
	}
}

func TestReasonError(t *testing.T) {
	var perr *proto.Error
	if err := reasonError("port_unavailable: port 20017 is taken"); !errors.As(err, &perr) || perr.Code != "port_unavailable" || perr.Message != "port 20017 is taken" {
		t.Errorf("got %v", err)
	}
	if err := reasonError("forbidden"); !errors.As(err, &perr) || perr.Code != "forbidden" || perr.Message != "" {
		t.Errorf("got %v", err)
	}
	if err := reasonError("closed by the operator"); errors.As(err, &perr) {
		t.Errorf("free text was taken for an error code: %v", err)
	}
}
