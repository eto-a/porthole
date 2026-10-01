// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

const testWait = 10 * time.Second

// shortDir returns a fresh directory with a short path: socket paths are limited to about 104 bytes and t.TempDir
// includes the test name.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func newToken(t *testing.T) string {
	t.Helper()
	tok, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return tok.String()
}

// waitFor polls cond until it holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// recorder collects sd_notify states.
type recorder struct {
	mu     sync.Mutex
	states []string
}

func (r *recorder) notify(state string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, state)
	return true, nil
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.states)
}

// harness is a running daemon with a client of its API.
type harness struct {
	t      *testing.T
	fs     *fakeServer
	d      *Daemon
	cl     *localapi.Client
	file   string
	sock   string
	notes  *recorder
	cancel context.CancelFunc
	done   chan error
}

// startDaemon starts a daemon against fs. tunnels is the content of the tunnels file; "" means no file.
func startDaemon(t *testing.T, fs *fakeServer, tunnels string, mut ...func(*Options)) *harness {
	t.Helper()
	dir := shortDir(t)
	h := &harness{t: t, fs: fs, file: filepath.Join(dir, "tunnels.yaml"), sock: filepath.Join(dir, "d.sock"), notes: &recorder{}}
	if tunnels != "" {
		h.writeFile(tunnels)
	}
	opts := Options{
		ServerURL:   fs.url(),
		Token:       newToken(t),
		TunnelsPath: h.file,
		SocketPath:  h.sock,
		Version:     "test",
		Notify:      h.notes.notify,
	}
	for _, m := range mut {
		m(&opts)
	}
	d, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h.d = d
	h.cl = localapi.NewClient(h.sock)
	t.Cleanup(h.cl.Close)

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	go func() { h.done <- d.Run(ctx) }()
	t.Cleanup(func() { _ = h.stop() })

	waitFor(t, "the local api", func() bool {
		_, err := h.cl.Status(context.Background())
		return err == nil
	})
	return h
}

// stop shuts the daemon down and returns Run's result (once).
func (h *harness) stop() error {
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err // keep it for later callers
		return err
	case <-time.After(testWait):
		h.t.Error("daemon did not stop")
		return errors.New("timeout")
	}
}

func (h *harness) writeFile(content string) {
	h.t.Helper()
	if err := os.WriteFile(h.file, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) tunnels() map[string]localapi.Tunnel {
	h.t.Helper()
	ts, err := h.cl.Tunnels(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	m := map[string]localapi.Tunnel{}
	for i := range ts {
		m[ts[i].Name] = ts[i]
	}
	return m
}

func (h *harness) waitReady(names ...string) {
	h.t.Helper()
	waitFor(h.t, "tunnels "+strings.Join(names, ",")+" to be ready", func() bool {
		ts := h.tunnels()
		for _, n := range names {
			if ts[n].State != localapi.TunnelReady {
				return false
			}
		}
		return true
	})
}

func apiErr(t *testing.T, err error, code string) *localapi.Error {
	t.Helper()
	var e *localapi.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want API error %q", err, code)
	}
	return e
}

const twoTunnels = `version: 1
tunnels:
  blog:
    type: http
    addr: 3000
  db:
    type: tcp
    addr: nas.local:5432
    remote_port: 20017
  old:
    type: http
    addr: 8081
    enabled: false
`

func TestStatusMapsManagerState(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, twoTunnels)
	h.waitReady("blog", "db")

	st, err := h.cl.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.State != localapi.StateConnected || st.ClientName != "home" || st.Version != "test" || st.PID != os.Getpid() {
		t.Errorf("status %+v", st)
	}
	if st.Server != fs.url() || st.TunnelsFile != h.file || st.RetryAt != nil || st.LastError != "" || st.StartedAt.IsZero() {
		t.Errorf("status %+v", st)
	}
	want := []localapi.Tunnel{
		{
			Name: "blog", Type: "http", LocalAddr: "127.0.0.1:3000", PublicURL: "https://blog-home.tun.test",
			State: localapi.TunnelReady, Source: localapi.SourceFile, Lifetime: localapi.LifetimeFile,
		},
		{
			Name: "db", Type: "tcp", LocalAddr: "nas.local:5432", RemotePort: 20017, PublicURL: "tcp://tun.test:20017",
			State: localapi.TunnelReady, Source: localapi.SourceFile, Lifetime: localapi.LifetimeFile,
		},
	}
	if !slices.Equal(st.Tunnels, want) { // the disabled "old" tunnel is not part of the set
		t.Errorf("tunnels\n got %+v\nwant %+v", st.Tunnels, want)
	}
	ts, err := h.cl.Tunnels(context.Background())
	if err != nil || !slices.Equal(ts, want) {
		t.Errorf("Tunnels() = %+v, %v", ts, err)
	}
}

func TestFailedRegistrationIsReported(t *testing.T) {
	fs := newFakeServer(t)
	fs.refuseName("bad", proto.CodeNameTaken)
	h := startDaemon(t, fs, "version: 1\ntunnels:\n  good: {type: http, addr: 1}\n  bad: {type: http, addr: 2}\n")
	waitFor(t, "bad to fail", func() bool { return h.tunnels()["bad"].State == localapi.TunnelFailed })
	h.waitReady("good")
	tn := h.tunnels()["bad"]
	if !strings.Contains(tn.Error, "name_taken") || tn.PublicURL != "" {
		t.Errorf("bad tunnel: %+v", tn)
	}
	if h.tunnels()["good"].Error != "" {
		t.Errorf("good tunnel has an error: %+v", h.tunnels()["good"])
	}
}

func TestMissingFileIsEmptySet(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "")
	st, err := h.cl.Status(context.Background())
	if err != nil || len(st.Tunnels) != 0 {
		t.Fatalf("status %+v, %v", st, err)
	}
	// Reload with a file that still does not exist is a no-op, and creating it later works.
	res, err := h.cl.Reload(context.Background())
	if err != nil || len(res.Added)+len(res.Removed)+len(res.Changed) != 0 {
		t.Fatalf("reload without file: %+v, %v", res, err)
	}
	h.writeFile("version: 1\ntunnels:\n  blog: {type: http, addr: 3000}\n")
	res, err = h.cl.Reload(context.Background())
	if err != nil || !slices.Equal(res.Added, []string{"blog"}) {
		t.Fatalf("reload after creating the file: %+v, %v", res, err)
	}
	h.waitReady("blog")
}

func TestBrokenFileAtStartIsConfigError(t *testing.T) {
	fs := newFakeServer(t)
	dir := shortDir(t)
	file := filepath.Join(dir, "tunnels.yaml")
	if err := os.WriteFile(file, []byte("version: 1\ntunnels:\n  blog: {type: nope, addr: 1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{ServerURL: fs.url(), Token: newToken(t), TunnelsPath: file, SocketPath: filepath.Join(dir, "s")})
	var ce *ConfigError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("error = %v, want a *ConfigError about the type", err)
	}
	if fs.connCount() != 0 {
		t.Error("the daemon connected despite the broken file")
	}
}

func TestNewRejectsBadCredentials(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "s")
	for name, o := range map[string]Options{
		"no server": {Token: newToken(t), SocketPath: sock},
		"bad token": {ServerURL: "http://127.0.0.1:1", Token: "nope", SocketPath: sock},
		"bad url":   {ServerURL: "ftp://x", Token: newToken(t), SocketPath: sock},
	} {
		_, err := New(o)
		var ce *ConfigError
		if !errors.As(err, &ce) {
			t.Errorf("%s: error = %v, want a *ConfigError", name, err)
		}
	}
	if _, err := New(Options{ServerURL: "http://127.0.0.1:1", Token: newToken(t)}); err == nil {
		t.Error("a missing socket path must be rejected")
	}
}

func TestServerPrecedence(t *testing.T) {
	fs := newFakeServer(t)
	dir := shortDir(t)
	file := filepath.Join(dir, "tunnels.yaml")
	if err := os.WriteFile(file, []byte("version: 1\nserver: "+fs.url()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := Options{Token: newToken(t), TunnelsPath: file, SocketPath: filepath.Join(dir, "s")}

	cfgOnly := base
	cfgOnly.ConfigServer = "http://config.invalid"
	d, err := New(cfgOnly)
	if err != nil || d.server != fs.url() {
		t.Fatalf("file must win over config.yaml: %v, %q", err, d.server)
	}
	explicit := cfgOnly
	explicit.ServerURL = "http://explicit.invalid"
	d, err = New(explicit)
	if err != nil || d.server != "http://explicit.invalid" {
		t.Fatalf("an explicit server must win over the file: %v, %q", err, d.server)
	}
	noFileServer := explicit
	noFileServer.ServerURL, noFileServer.TunnelsPath = "", ""
	d, err = New(noFileServer)
	if err != nil || d.server != "http://config.invalid" {
		t.Fatalf("config.yaml is the last resort: %v, %q", err, d.server)
	}
}

func TestReloadAppliesDiff(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, twoTunnels)
	h.waitReady("blog", "db")
	if n := fs.registrations("blog"); n != 1 {
		t.Fatalf("blog registered %d times before the reload", n)
	}

	// db is removed, blog is unchanged, web is added, old is enabled and so added too.
	h.writeFile(`version: 1
tunnels:
  blog: {type: http, addr: 3000}
  web:  {type: http, addr: 8080}
  old:  {type: http, addr: 8081}
`)
	res, err := h.cl.Reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := localapi.ReloadResult{
		Added: []string{"old", "web"}, Removed: []string{"db"}, Changed: []string{}, Unchanged: []string{"blog"},
	}
	if !slices.Equal(res.Added, want.Added) || !slices.Equal(res.Removed, want.Removed) ||
		len(res.Changed) != 0 || !slices.Equal(res.Unchanged, want.Unchanged) {
		t.Fatalf("reload result %+v, want %+v", res, want)
	}
	h.waitReady("blog", "old", "web")
	waitFor(t, "db to be unregistered", func() bool { return !slices.Contains(fs.liveTunnels(), "db") })
	if n := fs.registrations("blog"); n != 1 {
		t.Errorf("blog was registered %d times: an unchanged tunnel must not be touched", n)
	}

	// A changed tunnel is registered again.
	h.writeFile("version: 1\ntunnels:\n  blog: {type: http, addr: 3001}\n  web: {type: http, addr: 8080}\n  old: {type: http, addr: 8081}\n")
	res, err = h.cl.Reload(context.Background())
	if err != nil || !slices.Equal(res.Changed, []string{"blog"}) || len(res.Added)+len(res.Removed) != 0 {
		t.Fatalf("reload result %+v, %v", res, err)
	}
	waitFor(t, "blog to be re-registered", func() bool { return fs.registrations("blog") == 2 })
	h.waitReady("blog")
	if got := h.tunnels()["blog"].LocalAddr; got != "127.0.0.1:3001" {
		t.Errorf("blog local address = %q", got)
	}
}

func TestReloadKeepsOldSetOnBrokenFile(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, twoTunnels)
	h.waitReady("blog", "db")

	h.writeFile("version: 1\ntunnels:\n  blog: {type: http, addr: 3000}\n  bad: {type: carrier-pigeon, addr: 1}\n")
	_, err := h.cl.Reload(context.Background())
	e := apiErr(t, err, localapi.CodeInvalidRequest)
	if !strings.Contains(e.Message, "carrier-pigeon") || !strings.Contains(e.Message, "keeping the current tunnels") {
		t.Errorf("message %q", e.Message)
	}
	if ts := h.tunnels(); len(ts) != 2 || ts["blog"].State != localapi.TunnelReady || ts["db"].State != localapi.TunnelReady {
		t.Errorf("the old set was not kept: %+v", ts)
	}

	// Garbage that is not even YAML.
	h.writeFile("{{{")
	_, err = h.cl.Reload(context.Background())
	_ = apiErr(t, err, localapi.CodeInvalidRequest)

	// A file that existed at start and is gone now is an error as well; an empty file is how to stop everything.
	if err := os.Remove(h.file); err != nil {
		t.Fatal(err)
	}
	_, err = h.cl.Reload(context.Background())
	e = apiErr(t, err, localapi.CodeInvalidRequest)
	if !strings.Contains(e.Message, "does not exist") {
		t.Errorf("message %q", e.Message)
	}
	if len(h.tunnels()) != 2 {
		t.Error("the old set was not kept after the file disappeared")
	}
	h.writeFile("version: 1\n")
	res, err := h.cl.Reload(context.Background())
	if err != nil || !slices.Equal(res.Removed, []string{"blog", "db"}) {
		t.Fatalf("reload of an empty file: %+v, %v", res, err)
	}
}

func TestConflictRules(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, twoTunnels)
	h.waitReady("blog", "db")
	ctx := context.Background()

	// A file tunnel cannot be removed, with a hint where to change it.
	err := h.cl.RemoveTunnel(ctx, "blog")
	e := apiErr(t, err, localapi.CodeConflict)
	if !strings.Contains(e.Message, "defined in tunnels.yaml; edit it and run `porthole reload`") {
		t.Errorf("message %q", e.Message)
	}
	if _, ok := h.tunnels()["blog"]; !ok {
		t.Fatal("the file tunnel was removed")
	}
	_ = apiErr(t, h.cl.RemoveTunnel(ctx, "nope"), localapi.CodeNotFound)

	// A runtime tunnel may not take the name of a file tunnel, nor of another runtime tunnel.
	_, err = h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "http", Name: "blog", Addr: "9000"})
	e = apiErr(t, err, localapi.CodeNameTaken)
	if !strings.Contains(e.Message, "tunnels.yaml") {
		t.Errorf("message %q", e.Message)
	}
	tn, err := h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "http", Name: "tmp", Addr: "9000"})
	if err != nil || tn.Name != "tmp" || tn.Lifetime != localapi.LifetimeRuntime || tn.Source != localapi.SourceRuntime {
		t.Fatalf("add: %+v, %v", tn, err)
	}
	_, err = h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "tcp", Name: "tmp", Addr: "9001"})
	_ = apiErr(t, err, localapi.CodeNameTaken)
	h.waitReady("tmp")

	if err := h.cl.RemoveTunnel(ctx, "tmp"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.tunnels()["tmp"]; ok {
		t.Error("the runtime tunnel is still listed")
	}
	waitFor(t, "tmp to be unregistered", func() bool { return !slices.Contains(fs.liveTunnels(), "tmp") })
}

func TestAddTunnelValidationAndDefaults(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\n")
	ctx := context.Background()

	for name, req := range map[string]localapi.AddTunnelRequest{
		"no addr":          {Type: "http"},
		"bad addr":         {Type: "http", Addr: "not a port"},
		"bad name":         {Type: "http", Addr: "80", Name: "-x"},
		"remote port http": {Type: "http", Addr: "80", RemotePort: 1234},
		"remote port high": {Type: "tcp", Addr: "80", RemotePort: 70000},
		"private on tcp":   {Type: "tcp", Addr: "80", Private: true},
		"public_port http": {Type: "http", Addr: "80", PublicPort: true},
		"private+public":   {Type: "ssh", Private: true, PublicPort: true},
		"remote port ssh":  {Type: "ssh", RemotePort: 2222},
	} {
		req.Lifetime = localapi.LifetimeRuntime
		if _, err := h.d.AddTunnel(ctx, req); err == nil {
			t.Errorf("%s: want an error", name)
		} else if e := (*localapi.Error)(nil); !errors.As(err, &e) || e.Code != localapi.CodeInvalidRequest {
			t.Errorf("%s: error %v is not invalid_request", name, err)
		}
	}

	tn, err := h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "http", Addr: "8080"})
	if err != nil || tn.Name != "http-8080" || tn.LocalAddr != "127.0.0.1:8080" || tn.State != localapi.TunnelPending {
		t.Fatalf("default http tunnel: %+v, %v", tn, err)
	}
	tn, err = h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "ssh"})
	if err != nil || tn.Name != "ssh" || tn.Type != "ssh" || tn.LocalAddr != "127.0.0.1:22" || tn.Private {
		t.Fatalf("ssh tunnel: %+v, %v", tn, err)
	}
	tn, err = h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "ssh", Name: "ssh-pub", PublicPort: true, RemotePort: 20043})
	if err != nil || tn.Type != "tcp" || tn.RemotePort != 20043 {
		t.Fatalf("ssh --public-port tunnel: %+v, %v", tn, err)
	}
	tn, err = h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "ssh", Name: "ssh-priv", Private: true})
	if err != nil || tn.Type != "ssh" || !tn.Private {
		t.Fatalf("private ssh tunnel: %+v, %v", tn, err)
	}
	tn, err = h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "tcp", Addr: "nas:5432", Name: "pg", RemotePort: 20042})
	if err != nil || tn.RemotePort != 20042 {
		t.Fatalf("tcp tunnel: %+v, %v", tn, err)
	}
	h.waitReady("http-8080", "ssh", "ssh-pub", "pg")
	if got := h.tunnels()["pg"].PublicURL; got != "tcp://tun.test:20042" {
		t.Errorf("pg public url %q", got)
	}
}

func TestReloadAdoptsRuntimeTunnelOfTheSameName(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\n")
	ctx := context.Background()

	for _, req := range []localapi.AddTunnelRequest{
		{Type: "http", Name: "same", Addr: "3000"},
		{Type: "http", Name: "differs", Addr: "3001"},
		{Type: "http", Name: "mine", Addr: "3002"},
	} {
		if _, err := h.cl.AddTunnel(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	h.waitReady("same", "differs", "mine")

	// The file wins on a name clash: "same" has the same spec (not re-registered), "differs" another one.
	h.writeFile("version: 1\ntunnels:\n  same: {type: http, addr: 3000}\n  differs: {type: http, addr: 4001}\n")
	res, err := h.cl.Reload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Unchanged, []string{"same"}) || !slices.Equal(res.Changed, []string{"differs"}) ||
		len(res.Added)+len(res.Removed) != 0 {
		t.Fatalf("reload result %+v", res)
	}
	h.waitReady("same", "differs", "mine")
	ts := h.tunnels()
	if fs.registrations("same") != 1 || fs.registrations("differs") != 2 {
		t.Errorf("registrations: same=%d differs=%d", fs.registrations("same"), fs.registrations("differs"))
	}
	for _, name := range []string{"same", "differs"} {
		if ts[name].Lifetime != localapi.LifetimeFile || ts[name].Source != localapi.SourceFile {
			t.Errorf("%s: %+v, want a file tunnel", name, ts[name])
		}
		_ = apiErr(t, h.cl.RemoveTunnel(ctx, name), localapi.CodeConflict)
	}
	if ts["differs"].LocalAddr != "127.0.0.1:4001" {
		t.Errorf("differs local address = %q", ts["differs"].LocalAddr)
	}
	// A runtime tunnel the file does not mention survives every reload.
	if ts["mine"].Lifetime != localapi.LifetimeRuntime {
		t.Errorf("mine: %+v", ts["mine"])
	}
	// Removing the entry from the file removes the (former runtime) tunnel; "mine" is still there.
	h.writeFile("version: 1\n")
	res, err = h.cl.Reload(ctx)
	if err != nil || !slices.Equal(res.Removed, []string{"differs", "same"}) {
		t.Fatalf("reload result %+v, %v", res, err)
	}
	if ts := h.tunnels(); len(ts) != 1 || ts["mine"].Name == "" {
		t.Errorf("tunnels after the reload: %+v", ts)
	}
}

func TestAttachedTunnelIsRemovedOnDisconnect(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, twoTunnels)
	h.waitReady("blog")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var first localapi.Event
	ready := make(chan localapi.Event, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- h.cl.Attach(ctx, localapi.AddTunnelRequest{Type: "http", Name: "att", Addr: "7000"}, func(ev localapi.Event) error {
			switch ev.Type {
			case localapi.EventAttached:
				first = ev
			case localapi.EventTunnelReady:
				ready <- ev
			}
			return nil
		})
	}()
	var ev localapi.Event
	select {
	case ev = <-ready:
	case <-time.After(testWait):
		t.Fatal("no tunnel_ready event on the attached stream")
	}
	if ev.Name != "att" || ev.PublicURL != "https://att-home.tun.test" {
		t.Errorf("ready event %+v", ev)
	}
	if first.Tunnel == nil || first.Tunnel.Name != "att" || first.Tunnel.Lifetime != localapi.LifetimeAttached {
		t.Errorf("attached event %+v", first)
	}
	if got := h.tunnels()["att"]; got.Lifetime != localapi.LifetimeAttached || got.Source != localapi.SourceRuntime || got.State != localapi.TunnelReady {
		t.Errorf("attached tunnel %+v", got)
	}

	cancel() // the CLI went away
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Errorf("Attach returned %v", err)
	}
	waitFor(t, "the attached tunnel to disappear", func() bool { _, ok := h.tunnels()["att"]; return !ok })
	waitFor(t, "att to be unregistered", func() bool { return !slices.Contains(fs.liveTunnels(), "att") })
	if ts := h.tunnels(); len(ts) != 2 || ts["blog"].State != localapi.TunnelReady || ts["db"].State != localapi.TunnelReady {
		t.Errorf("file tunnels disturbed: %+v", ts)
	}
}

func TestAttachedRefusedRegistrationIsReportedOnTheStream(t *testing.T) {
	fs := newFakeServer(t)
	fs.refuseName("nope", proto.CodeForbidden)
	h := startDaemon(t, fs, "version: 1\n")

	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	var closed localapi.Event
	err := h.cl.Attach(ctx, localapi.AddTunnelRequest{Type: "http", Name: "nope", Addr: "7000"}, func(ev localapi.Event) error {
		if ev.Type == localapi.EventTunnelClosed {
			closed = ev
			return localapi.ErrStopStream
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if closed.Name != "nope" || !strings.HasPrefix(closed.Error, "forbidden") {
		t.Errorf("closed event %+v", closed)
	}
	waitFor(t, "the failed attached tunnel to be removed", func() bool { _, ok := h.tunnels()["nope"]; return !ok })
}

func TestEventsStream(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\n")

	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	events := make(chan localapi.Event, 16)
	go func() {
		_ = h.cl.Events(ctx, func(ev localapi.Event) error { events <- ev; return nil })
	}()
	time.Sleep(200 * time.Millisecond) // let the subscription register
	if _, err := h.cl.AddTunnel(ctx, localapi.AddTunnelRequest{Type: "http", Name: "ev", Addr: "7000"}); err != nil {
		t.Fatal(err)
	}
	waitEvent := func(typ string) localapi.Event {
		t.Helper()
		for {
			select {
			case ev := <-events:
				if ev.Type == typ {
					return ev
				}
			case <-ctx.Done():
				t.Fatalf("no %s event", typ)
			}
		}
	}
	if ev := waitEvent(localapi.EventTunnelReady); ev.Name != "ev" || ev.PublicURL == "" {
		t.Errorf("ready event %+v", ev)
	}
	if err := h.cl.RemoveTunnel(ctx, "ev"); err != nil {
		t.Fatal(err)
	}
	if ev := waitEvent(localapi.EventTunnelClosed); ev.Name != "ev" || ev.Error != "" || ev.Reason != "removed" {
		t.Errorf("closed event %+v", ev)
	}
}

func TestNotifyAndShutdown(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, twoTunnels)
	if got := h.notes.all(); !slices.Equal(got, []string{localapi.NotifyReady}) {
		t.Fatalf("notifications after start: %v", got)
	}
	if err := h.stop(); err != nil {
		t.Fatalf("Run returned %v on a normal shutdown", err)
	}
	if got := h.notes.all(); !slices.Equal(got, []string{localapi.NotifyReady, localapi.NotifyStopping}) {
		t.Fatalf("notifications: %v", got)
	}
	if _, err := localapi.NewClient(h.sock).Status(context.Background()); err == nil {
		t.Error("the socket still answers after the shutdown")
	}
}

func TestSecondDaemonOnTheSameSocketFailsBeforeConnecting(t *testing.T) {
	fs := newFakeServer(t)
	h := startDaemon(t, fs, "version: 1\n")
	waitFor(t, "the first daemon to connect", func() bool { return fs.connCount() == 1 })

	d2, err := New(Options{ServerURL: fs.url(), Token: newToken(t), SocketPath: h.sock})
	if err != nil {
		t.Fatal(err)
	}
	err = d2.Run(context.Background())
	if !errors.Is(err, localapi.ErrAlreadyRunning) {
		t.Fatalf("second Run = %v, want ErrAlreadyRunning", err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := fs.connCount(); n != 1 {
		t.Errorf("the server saw %d sessions: the second daemon connected before it knew it could listen", n)
	}
}

func TestFatalServerErrorEndsRunAsConfigError(t *testing.T) {
	// A server that rejects every hello with a non-retryable error.
	rejecting := newRejectingServer(t, proto.CodeUnauthorized)
	dir := shortDir(t)
	d, err := New(Options{ServerURL: rejecting, Token: newToken(t), SocketPath: filepath.Join(dir, "s")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- d.Run(context.Background()) }()
	select {
	case err = <-done:
	case <-time.After(testWait):
		t.Fatal("Run did not end")
	}
	var ce *ConfigError
	var perr *proto.Error
	if !errors.As(err, &ce) || !errors.As(err, &perr) || perr.Code != proto.CodeUnauthorized {
		t.Fatalf("Run = %v, want a *ConfigError wrapping the unauthorized error", err)
	}
}
