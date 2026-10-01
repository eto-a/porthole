// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package e2e runs the real portholed and porthole binaries as separate processes and drives them the way an
// operator and a user would: token CLI next to a live server, HTTP/WebSocket/TCP tunnels, revocation.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

var (
	binDir     string
	portholed  string
	porthole   string
	tokenRe    = regexp.MustCompile(`ph_[a-z2-7]{12}_[a-z2-7]{52}`)
	httpURLRe  = regexp.MustCompile(`http://([a-z0-9-]+)\.localhost:\d+`)
	tcpURLRe   = regexp.MustCompile(`tcp://localhost:(\d+)`)
	sshCmdRe   = regexp.MustCompile(`ssh -p (\d+) tester@localhost`)
	sshJumpRe  = regexp.MustCompile(`ssh -J (\S+) tester@(\S+)`)
	repoRootRe = "../.."
)

// Environment variables for the protocol compatibility run (CI job "compat", see DESIGN.md section 6). Each side
// is built from the working tree unless its variable points at a prebuilt binary, for example one taken from the
// previous release. With both unset the behaviour is unchanged.
const (
	envServerBin = "PORTHOLE_E2E_SERVER_BIN" // portholed to run instead of building ./cmd/portholed
	envClientBin = "PORTHOLE_E2E_CLIENT_BIN" // porthole to run instead of building ./cmd/porthole
	envCompat    = "PORTHOLE_E2E_COMPAT"     // "1": client and server may be different versions
)

// skipInCompat skips a test that needs a feature the other side may lack. Call it first in any test that covers
// behaviour added after the baseline release; the compat job sets PORTHOLE_E2E_COMPAT=1.
func skipInCompat(t *testing.T, why string) {
	t.Helper()
	if os.Getenv(envCompat) == "1" {
		t.Skipf("skipped in cross-version mode: %s", why)
	}
}

// resolveBin returns the binary named by envVar if it is set (it must exist), otherwise builds pkg into dir.
func resolveBin(dir, envVar, name, pkg string) (string, error) {
	if p := os.Getenv(envVar); p != "" {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", fmt.Errorf("%s: %w", envVar, err)
		}
		if _, err := os.Stat(abs); err != nil { //nolint:gosec // the path comes from the developer's or CI's own environment
			return "", fmt.Errorf("%s: %w", envVar, err)
		}
		return abs, nil
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = repoRootRe
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build %s: %w", pkg, err)
	}
	return out, nil
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "porthole-e2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binDir = dir
	if portholed, err = resolveBin(binDir, envServerBin, "portholed", "./cmd/portholed"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if porthole, err = resolveBin(binDir, envClientBin, "porthole", "./cmd/porthole"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "e2e binaries: server %s, client %s\n", portholed, porthole)
	code := m.Run()
	_ = os.RemoveAll(binDir)
	os.Exit(code)
}

// freePort returns a currently free TCP port on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// proc is a running binary whose combined output is captured line by line.
type proc struct {
	cmd   *exec.Cmd
	mu    sync.Mutex
	lines []string
	added chan struct{}
	done  chan struct{}
	err   error
}

func start(t *testing.T, bin string, args ...string) *proc {
	t.Helper()
	p := &proc{cmd: exec.Command(bin, args...), added: make(chan struct{}, 1), done: make(chan struct{})}
	r, w := io.Pipe()
	p.cmd.Stdout, p.cmd.Stderr = w, w
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			p.mu.Lock()
			p.lines = append(p.lines, sc.Text())
			p.mu.Unlock()
			select {
			case p.added <- struct{}{}:
			default:
			}
		}
		if err := sc.Err(); err != nil {
			p.mu.Lock()
			p.lines = append(p.lines, "[e2e: output scan error: "+err.Error()+"]")
			p.mu.Unlock()
		}
	}()
	go func() {
		p.err = p.cmd.Wait()
		_ = w.Close()
		close(p.done)
	}()
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		<-p.done
		if t.Failed() {
			t.Logf("output of %s %v:\n%s", filepath.Base(bin), args, p.output())
		}
	})
	return p
}

func (p *proc) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.lines, "\n")
}

// waitFor waits until the output matches re and returns the submatches.
func (p *proc) waitFor(t *testing.T, re *regexp.Regexp, timeout time.Duration) []string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if m := re.FindStringSubmatch(p.output()); m != nil {
			return m
		}
		select {
		case <-p.added:
		case <-p.done:
			if m := re.FindStringSubmatch(p.output()); m != nil {
				return m
			}
			t.Fatalf("process exited (%v) before printing %s", p.err, re)
		case <-deadline:
			t.Fatalf("timed out waiting for %s", re)
		}
	}
}

func run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", filepath.Base(bin), args, err, out)
	}
	return string(out)
}

type env struct {
	cfgPath    string
	port       int
	server     string // client-facing URL
	clientConf string
	dataDir    string
}

// setup writes a server config, creates a token with the CLI and starts portholed.
func setup(t *testing.T, extraConfig ...string) (*env, string) {
	t.Helper()
	dir := t.TempDir()
	e := &env{port: freePort(t), clientConf: filepath.Join(dir, "client.yaml"), dataDir: filepath.Join(dir, "data")}
	lo := 41000 + int(time.Now().UnixNano()%2000)
	cfg := fmt.Sprintf(`version: 1
domain: localhost
listen: "127.0.0.1:%d"
public_scheme: http
tls:
  mode: off
public_port: %d
tcp_port_range: "%d-%d"
tcp_bind_host: 127.0.0.1
data_dir: %q
shutdown_grace: 2s
`, e.port, e.port, lo, lo+50, filepath.ToSlash(e.dataDir))
	cfg += strings.Join(extraConfig, "")
	e.cfgPath = filepath.Join(dir, "portholed.yaml")
	if err := os.WriteFile(e.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	e.server = fmt.Sprintf("http://localhost:%d", e.port)

	// The token is created before the server runs; a second one is created while it runs (shared SQLite).
	tok := tokenRe.FindString(run(t, portholed, "token", "create", "--name", "home", "-c", e.cfgPath))
	if tok == "" {
		t.Fatal("token create printed no token")
	}

	start(t, portholed, "serve", "-c", e.cfgPath, "--log-level", "debug")
	waitHealthy(t, e.port)
	return e, tok
}

func waitHealthy(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/healthz", port), nil)
		req.Host = "localhost"
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("portholed did not become healthy")
}

// backend is a local service exposed through tunnels: HTTP + WebSocket echo, and a raw TCP echo.
func backend(t *testing.T) (httpPort, tcpPort int) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello via %s xff=%s", r.Host, r.Header.Get("X-Forwarded-For"))
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			typ, b, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), typ, append([]byte("echo:"), b...)); err != nil {
				return
			}
		}
	})
	hl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(hl) }()
	t.Cleanup(func() { _ = srv.Close() })

	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tl.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return hl.Addr().(*net.TCPAddr).Port, tl.Addr().(*net.TCPAddr).Port
}

func (e *env) client(t *testing.T, tok string, args ...string) *proc {
	t.Helper()
	full := append([]string{"--config", e.clientConf}, args...)
	full = append(full, "--server", e.server, "--token", tok)
	if os.Getenv(envCompat) != "1" {
		// A daemon of the developer's machine must not take these over; releases before the daemon lack the flag.
		full = append(full, "--no-daemon")
	}
	return start(t, porthole, full...)
}

// viaTunnel sends an HTTP request to the server with the tunnel's Host header.
func (e *env) viaTunnel(t *testing.T, label, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", e.port, path), nil)
	req.Host = fmt.Sprintf("%s.localhost:%d", label, e.port)
	req.Header.Set("X-Forwarded-For", "6.6.6.6") // must not be trusted
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request via tunnel: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHTTPAndWebSocketTunnel(t *testing.T) {
	e, tok := setup(t)
	httpPort, _ := backend(t)

	c := e.client(t, tok, "http", fmt.Sprint(httpPort))
	label := c.waitFor(t, httpURLRe, 20*time.Second)[1]
	if want := fmt.Sprintf("http-%d-home", httpPort); label != want {
		t.Fatalf("label %q, want %q", label, want)
	}

	code, body := e.viaTunnel(t, label, "/hello")
	if code != http.StatusOK || !strings.HasPrefix(body, "hello via "+label+".localhost") {
		t.Fatalf("got %d %q", code, body)
	}
	if strings.Contains(body, "6.6.6.6") {
		t.Errorf("visitor-supplied X-Forwarded-For leaked through: %q", body)
	}

	// WebSocket upgrade through the tunnel.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, fmt.Sprintf("ws://127.0.0.1:%d/ws", e.port), &websocket.DialOptions{
		Host: fmt.Sprintf("%s.localhost:%d", label, e.port),
	})
	if err != nil {
		t.Fatalf("websocket via tunnel: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	defer ws.CloseNow()
	if err := ws.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, b, err := ws.Read(ctx); err != nil || string(b) != "echo:ping" {
		t.Fatalf("ws echo: %q %v", b, err)
	}

	// Unknown host → 404.
	if code, _ := e.viaTunnel(t, "nope-home", "/hello"); code != http.StatusNotFound {
		t.Errorf("unknown label: %d, want 404", code)
	}
}

func TestTCPAndSSHTunnels(t *testing.T) {
	e, tok := setup(t)
	_, tcpPort := backend(t)

	c := e.client(t, tok, "tcp", fmt.Sprint(tcpPort))
	pub := c.waitFor(t, tcpURLRe, 20*time.Second)[1]
	echo(t, pub)

	// `porthole ssh` is a TCP tunnel plus a ready ssh command; point it at the echo server instead of sshd.
	tok2 := tokenRe.FindString(run(t, portholed, "token", "create", "--name", "laptop", "-c", e.cfgPath))
	s := e.client(t, tok2, "ssh", "--local-port", fmt.Sprint(tcpPort), "--user", "tester")
	sshPort := s.waitFor(t, sshCmdRe, 20*time.Second)[1]
	echo(t, sshPort)
}

func echo(t *testing.T, port string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 5*time.Second)
	if err != nil {
		t.Fatalf("dial public port: %v", err)
	}
	defer conn.Close()
	echoConn(t, conn)
}

// echoConn sends 512 KiB through conn, half-closes it and expects the same bytes back.
func echoConn(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("porthole"), 64<<10) // 512 KiB
	go func() { _, _ = conn.Write(payload); halfClose(conn) }()
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo: %d bytes, err %v", len(got), err)
	}
}

func TestLoginCheckAndBadToken(t *testing.T) {
	e, tok := setup(t)
	out := run(t, porthole, "--config", e.clientConf, "login", e.server, tok, "--check")
	if !strings.Contains(out, "home") {
		t.Errorf("login --check output does not name the client:\n%s", out)
	}

	// A well-formed token the server does not know: the client must stop, not retry forever.
	bogus := "ph_aaaaaaaaaaaa_" + strings.Repeat("b", 52)
	c := e.client(t, bogus, "tcp", "1")
	select {
	case <-c.done:
		if c.err == nil {
			t.Fatal("client exited 0 with a bad token")
		}
		if !strings.Contains(c.output(), "token rejected") {
			t.Errorf("no actionable message:\n%s", c.output())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("client with a bad token kept running")
	}
}

func TestRevokeStopsLiveClient(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 30 s revalidation interval")
	}
	e, tok := setup(t)
	_, tcpPort := backend(t)
	c := e.client(t, tok, "tcp", fmt.Sprint(tcpPort))
	c.waitFor(t, tcpURLRe, 20*time.Second)

	// Revoke through the CLI while the server is running (separate process, same SQLite file).
	run(t, portholed, "token", "revoke", "home", "-c", e.cfgPath)
	if out := run(t, portholed, "token", "list", "--all", "-c", e.cfgPath); !strings.Contains(out, "revoked") {
		t.Fatalf("token list does not show the revocation:\n%s", out)
	}

	select {
	case <-c.done:
		if c.err == nil || !strings.Contains(c.output(), "token rejected") {
			t.Fatalf("client exit: %v\n%s", c.err, c.output())
		}
	case <-time.After(45 * time.Second):
		t.Fatal("client still running 45 s after its token was revoked")
	}
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// TestSSHGateway runs the whole chain with real binaries: porthole ssh registers an ssh tunnel (a TCP echo server
// stands in for sshd) and an x/crypto SSH client reaches it through the gateway as `ssh -J` would.
func TestSSHGateway(t *testing.T) {
	skipInCompat(t, "the ssh gateway does not exist in older releases")
	gwPort := freePort(t)
	e, tok := setup(t, fmt.Sprintf("ssh_gateway:\n  listen: %q\n", fmt.Sprintf("127.0.0.1:%d", gwPort)))
	_, tcpPort := backend(t)

	c := e.client(t, tok, "ssh", "--local-port", fmt.Sprint(tcpPort), "--user", "tester")
	m := c.waitFor(t, sshJumpRe, 20*time.Second)
	if want := fmt.Sprintf("localhost:%d", gwPort); m[1] != want || m[2] != "home" {
		t.Fatalf("ssh command %q: jump %q target %q, want %q and home", m[0], m[1], m[2], want)
	}

	// The fingerprint printed by the subcommand is the one the gateway presents.
	fp := strings.TrimSpace(run(t, portholed, "ssh-hostkey", "-c", e.cfgPath))
	var seen string
	conn, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", gwPort), &ssh.ClientConfig{
		User: "tester",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(k)
			return nil
		},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	if seen != fp || !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("host key fingerprint %q, ssh-hostkey printed %q", seen, fp)
	}
	ch, err := conn.Dial("tcp", "home:22")
	if err != nil {
		t.Fatalf("direct-tcpip to home: %v", err)
	}
	defer ch.Close()
	_ = ch.SetDeadline(time.Now().Add(10 * time.Second))
	echoConn(t, ch)
	if _, err := conn.Dial("tcp", "nobody:22"); err == nil {
		t.Error("unknown target must be refused")
	}
}
