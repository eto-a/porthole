// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/eto-a/porthole/internal/store"
	"github.com/eto-a/porthole/internal/traffic"
)

// SSH gateway (ADR 0003): a listener that accepts only direct-tcpip channels and splices each of them into a data
// stream to the client that owns the target "ssh" tunnel. It is not a shell: sessions, exec, forwarding requests,
// agent and X11 are refused.

const (
	// HostKeyFile is the name of the gateway host key inside the data directory.
	HostKeyFile = "ssh_host_ed25519_key"

	// sshTokenUser is the SSH user name that selects password (token) authentication. OpenSSH and x/crypto
	// clients always try "none" first, so a gateway that accepted none for everybody would never ask for the
	// token; for this user none is refused and the client falls through to the password prompt.
	sshTokenUser = "token"

	// sshConnectScopePrefix starts the scope that lets a token reach the private ssh tunnels of another client.
	sshConnectScopePrefix = "connect:"

	defaultSSHIdleTimeout = 60 * time.Second
	sshMaxConns           = 1024
	sshMaxAuthTries       = 3
	sshExtTokenID         = "porthole-token-id"
	sshExtClient          = "porthole-client"
	sshExtScopes          = "porthole-scopes"
)

// directTCPIP is the payload of a "direct-tcpip" channel open request (RFC 4254 section 7.2).
type directTCPIP struct {
	Host     string
	Port     uint32
	OrigHost string
	OrigPort uint32
}

// sshGateway is the state of a running gateway.
type sshGateway struct {
	cfg  *ssh.ServerConfig
	conn chan struct{} // semaphore bounding concurrent connections
}

// LoadHostKey reads the gateway host key from dir. It does not create one.
func LoadHostKey(dir string) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(filepath.Join(dir, HostKeyFile))
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", HostKeyFile, err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%s: want an ed25519 key, got %s", HostKeyFile, signer.PublicKey().Type())
	}
	return signer, nil
}

// loadOrCreateHostKey loads the host key from dir, generating it (OpenSSH PEM, mode 0600) on first use.
func loadOrCreateHostKey(dir string) (ssh.Signer, error) {
	signer, err := LoadHostKey(dir)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return signer, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "portholed")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, HostKeyFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return LoadHostKey(dir) // another process won the race
	}
	if err != nil {
		return nil, fmt.Errorf("create host key: %w", err)
	}
	if _, err := f.Write(pem.EncodeToMemory(block)); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("write host key: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("write host key: %w", err)
	}
	return LoadHostKey(dir)
}

// HostKeyFingerprint returns the SHA256 fingerprint of the existing gateway host key in dir.
func HostKeyFingerprint(dir string) (string, error) {
	signer, err := LoadHostKey(dir)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), nil
}

// startSSHGateway listens on cfg.SSHGateway.Listen when the gateway is enabled and starts serving it.
func (s *Server) startSSHGateway(ctx context.Context) error {
	if !s.cfg.SSHGateway.Enabled() {
		return nil
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.SSHGateway.Listen)
	if err != nil {
		return fmt.Errorf("server: ssh gateway listen %s: %w", s.cfg.SSHGateway.Listen, err)
	}
	return s.StartSSHGateway(ln)
}

// StartSSHGateway serves the SSH gateway on ln in the background until the server closes. It takes ownership of
// ln and returns once the host key is loaded.
func (s *Server) StartSSHGateway(ln net.Listener) error {
	signer, err := loadOrCreateHostKey(s.cfg.DataDir)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("server: ssh gateway host key: %w", err)
	}
	gw := &sshGateway{conn: make(chan struct{}, sshMaxConns)}
	gw.cfg = &ssh.ServerConfig{
		NoClientAuth:         true,
		NoClientAuthCallback: s.sshNoneAuth,
		PasswordCallback:     s.sshPasswordAuth,
		MaxAuthTries:         sshMaxAuthTries,
		ServerVersion:        "SSH-2.0-portholed",
	}
	gw.cfg.AddHostKey(signer)

	if !s.start(func() { s.sshAcceptLoop(ln, gw) }) {
		_ = ln.Close()
		return errors.New("server: closed")
	}
	s.log.Info("ssh gateway listening", "addr", ln.Addr().String(),
		"host_key_fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
	return nil
}

func (s *Server) sshAcceptLoop(ln net.Listener, gw *sshGateway) {
	stop := context.AfterFunc(s.ctx, func() { _ = ln.Close() })
	defer stop()
	defer func() { _ = ln.Close() }()
	backoff := acceptBackoffFloor
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("ssh gateway accept failed", "err", err)
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, acceptBackoffMax)
			continue
		}
		backoff = acceptBackoffFloor

		select {
		case gw.conn <- struct{}{}:
		default:
			s.log.Warn("ssh gateway at its connection limit, dropping connection", "limit", sshMaxConns)
			s.recordConn(traffic.Conn{
				Kind: traffic.KindSSH, VisitorIP: ipOf(conn.RemoteAddr().String()), Outcome: traffic.OutcomeLimit,
			}, s.now())
			_ = conn.Close()
			continue
		}
		if !s.start(func() {
			defer func() { <-gw.conn }()
			s.serveSSHConn(gw, conn)
		}) {
			<-gw.conn
			_ = conn.Close()
			return
		}
	}
}

// sshNoneAuth accepts SSH "none" authentication: a public tunnel needs no gateway credentials, so the user sees
// only the target's own prompt. The user name "token" asks for password authentication instead.
func (s *Server) sshNoneAuth(md ssh.ConnMetadata) (*ssh.Permissions, error) {
	if md.User() == sshTokenUser {
		return nil, errors.New("token required")
	}
	return &ssh.Permissions{}, nil
}

// sshPasswordAuth checks the password as a porthole token, with the same code and the same per-IP failure
// limiter as the control handshake. The permissions carry the token id (channels re-read the token from the
// store), the client name and the scopes granted at login.
func (s *Server) sshPasswordAuth(md ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ip := ipOf(md.RemoteAddr().String())
	if wait, blocked := s.limiter.blocked(ip, s.now()); blocked {
		s.log.Warn("ssh gateway login refused: too many failed attempts", "ip", ip, "wait", wait)
		s.recordConn(traffic.Conn{Kind: traffic.KindSSH, VisitorIP: ip, Outcome: traffic.OutcomeLimit}, s.now())
		return nil, errors.New("too many failed attempts")
	}
	tok, perr, fromClient := s.authenticate(s.ctx, string(password))
	if perr != nil {
		if fromClient {
			s.limiter.fail(ip, s.now())
			s.recordConn(traffic.Conn{Kind: traffic.KindSSH, VisitorIP: ip, Outcome: traffic.OutcomeAuthFailed}, s.now())
			s.log.Warn("ssh gateway login failed", "ip", ip, "code", perr.Code)
		}
		return nil, errors.New("invalid token")
	}
	return &ssh.Permissions{Extensions: map[string]string{
		sshExtTokenID: tok.ID,
		sshExtClient:  tok.Name,
		sshExtScopes:  strings.Join(tok.Scopes, ","),
	}}, nil
}

// idleGuard closes a connection that has had no open channel for d.
type idleGuard struct {
	mu sync.Mutex
	n  int
	d  time.Duration
	t  *time.Timer
}

func newIdleGuard(d time.Duration, onIdle func()) *idleGuard {
	g := &idleGuard{d: d}
	g.t = time.AfterFunc(d, onIdle)
	return g
}

func (g *idleGuard) enter() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	g.t.Stop()
}

func (g *idleGuard) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n--; g.n == 0 {
		g.t.Reset(g.d)
	}
}

func (g *idleGuard) stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.t.Stop()
}

// serveSSHConn runs one gateway connection from handshake to teardown.
func (s *Server) serveSSHConn(gw *sshGateway, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	ip := ipOf(conn.RemoteAddr().String())
	if wait, blocked := s.limiter.blocked(ip, s.now()); blocked {
		s.log.Warn("ssh gateway connection refused: too many failed attempts", "ip", ip, "wait", wait)
		s.recordConn(traffic.Conn{Kind: traffic.KindSSH, VisitorIP: ip, Outcome: traffic.OutcomeLimit}, s.now())
		return
	}
	stop := context.AfterFunc(s.ctx, func() { _ = conn.Close() })
	defer stop()

	_ = conn.SetDeadline(time.Now().Add(s.hsTimeout))
	sc, chans, reqs, err := ssh.NewServerConn(conn, gw.cfg)
	if err != nil {
		s.log.Debug("ssh gateway handshake failed", "ip", ip, "err", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	var cw sync.WaitGroup
	defer cw.Wait()
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs) // tcpip-forward, keepalives and the like: answered "no"

	idle := newIdleGuard(s.sshIdle, func() {
		s.log.Debug("ssh gateway closing idle connection", "ip", ip)
		_ = sc.Close()
	})
	defer idle.stop()

	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			_ = nc.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported")
			continue
		}
		cw.Go(func() { s.sshChannel(sc, nc, idle) })
	}
}

// sshChannel handles one direct-tcpip channel. Every refusal, whatever the reason, is the same reply.
func (s *Server) sshChannel(sc *ssh.ServerConn, nc ssh.NewChannel, idle *idleGuard) {
	start := s.now()
	entry := traffic.Conn{Kind: traffic.KindSSH, VisitorIP: ipOf(sc.RemoteAddr().String())}
	deny := func(outcome string) {
		_ = nc.Reject(ssh.ConnectionFailed, "connect failed")
		entry.Outcome = outcome
		s.recordConn(entry, start)
	}
	var p directTCPIP
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
		deny(traffic.OutcomeRefused)
		return
	}
	entry.Tunnel = p.Host // the requested target; replaced by the tunnel's own name once it is reached
	t, ok := s.lookupSSH(p.Host)
	if !ok || (t.private && !s.sshMayConnect(sc, t)) {
		s.log.Debug("ssh gateway channel refused", "ip", ipOf(sc.RemoteAddr().String()), "target", p.Host)
		deny(traffic.OutcomeRefused)
		return
	}
	entry.TunnelID, entry.Tunnel, entry.Client = t.id, t.name, t.sess.name
	if !t.acquire() {
		t.sess.log.Warn("ssh tunnel at its channel limit", "tunnel", t.id, "limit", cap(t.sem))
		deny(traffic.OutcomeLimit)
		return
	}
	defer t.release()
	idle.enter()
	defer idle.leave()

	// The client sees the real peer, not the originator the SSH client claims.
	remote := sc.RemoteAddr().String()
	stream, err := t.openStream(remote)
	if err != nil {
		t.sess.log.Debug("open stream for ssh channel failed", "tunnel", t.id, "remote", remote, "err", err)
		deny(traffic.OutcomeRefused)
		return
	}
	ch, chReqs, err := nc.Accept()
	if err != nil {
		_ = stream.Close()
		return
	}
	go ssh.DiscardRequests(chReqs)
	t.sess.log.Debug("ssh channel opened", "tunnel", t.id, "remote", remote,
		"originator", net.JoinHostPort(p.OrigHost, strconv.FormatUint(uint64(p.OrigPort), 10)))

	conn := &channelConn{Channel: ch, local: sc.LocalAddr(), remote: sc.RemoteAddr()}
	stop := context.AfterFunc(t.ctx, func() {
		_ = conn.Close()
		_ = stream.Close()
	})
	defer stop()
	entry.BytesIn, entry.BytesOut = pipe(conn, stream)
	entry.Outcome = traffic.OutcomeOK
	s.recordConn(entry, start)
}

// sshMayConnect reports whether the password session of sc may reach the private tunnel t: its token, re-read from
// the store now, must belong to the owner of t or carry connect:<owner>. Sessions without a token never may.
func (s *Server) sshMayConnect(sc *ssh.ServerConn, t *tunnel) bool {
	if sc.Permissions == nil {
		return false
	}
	id := sc.Permissions.Extensions[sshExtTokenID]
	if id == "" {
		return false
	}
	tok, perr, err := s.recheck(s.ctx, id)
	if err != nil {
		s.log.Error("ssh gateway: store lookup failed", "err", err)
		return false
	}
	if perr != nil {
		return false
	}
	return mayConnect(tok, t.sess.name)
}

func mayConnect(tok *store.Token, owner string) bool {
	return tok.Name == owner || tok.HasScope(sshConnectScopePrefix+owner)
}

// channelConn adapts an ssh.Channel to net.Conn so that pipe can splice it. Deadlines are not supported: the
// connection lifetime is bounded by the tunnel and the SSH connection instead.
type channelConn struct {
	ssh.Channel
	local, remote net.Addr
}

func (c *channelConn) LocalAddr() net.Addr              { return c.local }
func (c *channelConn) RemoteAddr() net.Addr             { return c.remote }
func (c *channelConn) SetDeadline(time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(time.Time) error { return nil }
