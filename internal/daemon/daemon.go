// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package daemon is the porthole client daemon: one long-lived session to the server carrying a mutable set of
// tunnels, controlled over the local API (internal/localapi) and by the tunnels file (internal/clientconfig).
// The design is in docs/adr/0002-client-daemon-and-tunnels-file.md.
//
// A [Daemon] implements [localapi.Backend] on top of a [client.Manager]. It remembers where every tunnel came from:
//
//   - lifetime "file": defined in the tunnels file; it can only be changed by editing the file and reloading;
//   - lifetime "runtime": added over the API and kept until it is removed or the daemon restarts;
//   - lifetime "attached": added over the API and removed by the local API handler when the caller disconnects.
//
// Reload makes the file-defined part of the set equal to the file and leaves the other tunnels alone. If a file
// tunnel has the same name as a runtime or attached tunnel, the file wins (see [Daemon.Reload]).
package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/clientconfig"
	"github.com/eto-a/porthole/internal/localapi"
	"github.com/eto-a/porthole/internal/proto"
)

const (
	// startTimeout bounds the wait for the manager goroutine to start (it takes microseconds in practice).
	startTimeout = 5 * time.Second
	// subscriberBuffer is the event buffer of every local API subscriber.
	subscriberBuffer = 64

	defaultSocketMode os.FileMode = 0o600
)

// Options configures a [Daemon].
type Options struct {
	// ServerURL is the server URL given explicitly (flag or environment). It wins over the tunnels file and
	// ConfigServer.
	ServerURL string
	// ConfigServer is the server URL of config.yaml. It is used when neither ServerURL nor the tunnels file names
	// a server. One of the three must be set.
	ConfigServer string
	// Token is the client token (ph_<id>_<secret>).
	Token string
	// TunnelsPath is the tunnels file. A missing file is an empty set. Empty means there is no file at all: only
	// runtime tunnels, and Reload fails.
	TunnelsPath string
	// SocketPath is the unix socket of the local API.
	SocketPath string
	// SocketMode is the permission of the socket; zero means 0600.
	SocketMode os.FileMode
	// Version is the client version reported to the server and in Status.
	Version string
	// Logger receives diagnostics. Nil discards them.
	Logger *slog.Logger
	// TLSConfig is used for wss; nil means the system defaults.
	TLSConfig *tls.Config
	// Notify sends a service manager notification (sd_notify). Nil means [localapi.Notify].
	Notify func(state string) (sent bool, err error)
}

// ConfigError is a problem that retrying or restarting cannot fix: a broken tunnels file at start, missing
// credentials, a token the server rejects, a server host that does not exist or whose certificate is not trusted.
// The CLI maps it to exit status 78 (EX_CONFIG) so that a supervisor does not restart the daemon in a loop.
type ConfigError struct{ Err error }

func (e *ConfigError) Error() string { return e.Err.Error() }
func (e *ConfigError) Unwrap() error { return e.Err }

// entry is what the daemon knows about a tunnel besides the manager's state.
type entry struct {
	lifetime string
	// uid is the owner of a tunnel added through the local API; owned is false when the caller's uid is unknown.
	uid   int
	owned bool
}

func (e entry) source() string {
	if e.lifetime == localapi.LifetimeFile {
		return localapi.SourceFile
	}
	return localapi.SourceRuntime
}

// Daemon is a client session with a mutable tunnel set. Build one with [New] and run it with [Daemon.Run].
type Daemon struct {
	opts      Options
	log       *slog.Logger
	mgr       *client.Manager
	server    string // the server URL in use; fixed for the life of the process
	startedAt time.Time
	selfUID   int // the user the daemon runs as (-1 on Windows)

	// mu serializes every change of the tunnel set (AddTunnel, RemoveTunnel, Reload) and guards the fields below. It
	// is held across calls into the manager, which never block on it.
	mu         sync.Mutex
	meta       map[string]entry
	fileExists bool // the tunnels file existed when it was last loaded
}

var _ localapi.Backend = (*Daemon)(nil)

// New validates the options, loads the tunnels file and prepares the manager. It does not connect or listen. A
// broken tunnels file, a missing server or token and the like are returned as *ConfigError.
func New(opts Options) (*Daemon, error) {
	if opts.SocketPath == "" {
		return nil, errors.New("daemon: no socket path")
	}
	if opts.SocketMode == 0 {
		opts.SocketMode = defaultSocketMode
	}
	if opts.Notify == nil {
		opts.Notify = localapi.Notify
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	file, existed, err := loadFile(opts.TunnelsPath)
	if err != nil {
		return nil, &ConfigError{Err: err}
	}
	specs, err := file.Specs()
	if err != nil {
		return nil, &ConfigError{Err: fmt.Errorf("tunnels file %s: %w", opts.TunnelsPath, err)}
	}
	server := effectiveServer(opts, file)
	if server == "" {
		return nil, &ConfigError{Err: errors.New("no server configured: run `porthole login <server-url> <token>`, " +
			"set PORTHOLE_SERVER, or add `server:` to the tunnels file")}
	}
	mgr, err := client.NewManager(client.Options{
		ServerURL: server,
		Token:     opts.Token,
		Tunnels:   specs,
		Version:   opts.Version,
		Logger:    log,
		TLSConfig: opts.TLSConfig,
		// The machine owner decides in the tunnels file (allow_remote) what the server may ask for; see ADR 0005.
		AcceptRemoteOpen: true,
		RemoteOpen:       file.RemotePolicy(),
		// The daemon keeps retrying until it is stopped (see ADR 0002), except for failures that retrying cannot fix.
		MaxInitialAttempts: 0,
	})
	if err != nil {
		return nil, &ConfigError{Err: err}
	}
	d := &Daemon{
		opts: opts, log: log, mgr: mgr, server: server, startedAt: time.Now().UTC(), selfUID: os.Geteuid(),
		meta: make(map[string]entry, len(specs)), fileExists: existed,
	}
	for _, sp := range specs {
		d.meta[sp.Name] = entry{lifetime: localapi.LifetimeFile}
	}
	switch {
	case opts.TunnelsPath == "":
		log.Info("no tunnels file configured")
	case !existed:
		log.Info("tunnels file does not exist, starting without file tunnels", "path", opts.TunnelsPath)
	default:
		log.Info("tunnels file loaded", "path", opts.TunnelsPath, "tunnels", len(specs))
	}
	return d, nil
}

// effectiveServer applies the precedence: explicit (flag, environment), tunnels file, config.yaml.
func effectiveServer(opts Options, file *clientconfig.File) string {
	switch {
	case opts.ServerURL != "":
		return opts.ServerURL
	case file != nil && file.Server != "":
		return file.Server
	default:
		return opts.ConfigServer
	}
}

// loadFile loads the tunnels file. A missing file (or an empty path) yields an empty file and existed == false.
func loadFile(path string) (file *clientconfig.File, existed bool, err error) {
	if path == "" {
		return &clientconfig.File{Version: clientconfig.Version}, false, nil
	}
	file, err = clientconfig.Load(path)
	switch {
	case err == nil:
		return file, true, nil
	case errors.Is(err, fs.ErrNotExist):
		return &clientconfig.File{Version: clientconfig.Version}, false, nil
	default:
		return nil, false, err
	}
}

// Run starts the daemon and blocks until ctx is done (it then returns nil) or something fatal happens.
//
// Order: the socket is bound first (so that a second daemon fails before it can take over the server session),
// then the manager connects to the server (forever, with backoff), then the local API is served, and then READY=1
// is sent to the service manager. SIGHUP reloads the tunnels file (Unix). On shutdown STOPPING=1 is sent, the API is
// drained and the session closed.
func (d *Daemon) Run(ctx context.Context) error {
	ln, err := localapi.Listen(d.opts.SocketPath, d.opts.SocketMode)
	if err != nil {
		return fmt.Errorf("local api socket: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	mgrDone := make(chan error, 1)
	go func() { mgrDone <- d.mgr.Run(runCtx) }()
	if err := d.waitRunning(runCtx, mgrDone); err != nil {
		_ = ln.Close()
		cancel()
		return err
	}

	serveDone := make(chan error, 1)
	go func() { serveDone <- localapi.Serve(runCtx, ln, localapi.NewHandler(d, d.log), d.log) }()

	var wg sync.WaitGroup
	wg.Go(func() { d.watchReload(runCtx) })

	d.notify(localapi.NotifyReady)
	d.log.Info("daemon ready", "socket", d.opts.SocketPath, "server", d.server)

	var result error
	select {
	case <-ctx.Done():
		d.log.Info("shutting down")
	case err := <-mgrDone:
		mgrDone = nil
		result = managerError(err)
	case err := <-serveDone:
		serveDone = nil
		if err == nil {
			err = errors.New("local api stopped unexpectedly")
		}
		result = err
	}

	d.notify(localapi.NotifyStopping)
	cancel()
	if mgrDone != nil {
		if err := managerError(<-mgrDone); err != nil && result == nil {
			result = err
		}
	}
	if serveDone != nil {
		if err := <-serveDone; err != nil && result == nil {
			result = err
		}
	}
	wg.Wait()
	return result
}

// waitRunning waits until the manager goroutine is running, so that no event of a later API call can be lost. It
// returns early with the manager's error if Run failed at once.
func (d *Daemon) waitRunning(ctx context.Context, done <-chan error) error {
	deadline := time.NewTimer(startTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for d.mgr.Snapshot().Conn == client.ConnIdle {
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("client manager stopped before it started")
			}
			return managerError(err)
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return errors.New("client manager did not start")
		case <-tick.C:
		}
	}
	return nil
}

// managerError classifies the error that ended the manager. Everything the manager returns on its own is a
// failure that retrying cannot fix (it retries the rest forever), so the operator has to act: ConfigError.
func managerError(err error) error {
	if err == nil {
		return nil
	}
	var perr *proto.Error
	var ice *client.InitialConnectError
	if errors.As(err, &perr) || errors.As(err, &ice) {
		return &ConfigError{Err: err}
	}
	return err
}

func (d *Daemon) notify(state string) {
	if _, err := d.opts.Notify(state); err != nil {
		d.log.Warn("service manager notification failed", "state", state, "err", err)
	}
}
