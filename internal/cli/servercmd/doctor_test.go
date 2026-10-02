// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// fakeDoctorDeps resolves every name through lookup and answers healthz with status 200; nothing touches the network.
func fakeDoctorDeps(lookup func(host string) ([]string, error)) doctorDeps {
	return doctorDeps{
		lookup: func(_ context.Context, host string) ([]string, error) { return lookup(host) },
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})},
		listen: func(string) (io.Closer, error) { return nopCloser{}, nil },
		now:    time.Now,
	}
}

func runDoctorCmd(t *testing.T, load func() (*config.Config, error), deps doctorDeps, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "portholed", SilenceUsage: true, SilenceErrors: true}
	jsonout.AddFlag(root)
	root.AddCommand(newDoctor(load, deps))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs(append([]string{"doctor"}, args...))
	err := root.Execute()
	return out.String(), err
}

func doctorConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Domain = "tun.example.com"
	cfg.DataDir = t.TempDir()
	cfg.TLS.ACME.Email = "admin@example.com"
	return cfg
}

func findCheck(t *testing.T, rep doctorReport, name string) doctorCheck {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", name, rep.Checks)
	return doctorCheck{}
}

func sameAddr(string) ([]string, error) { return []string{"192.0.2.1"}, nil }

func TestDoctorConfigError(t *testing.T) {
	load := func() (*config.Config, error) { return nil, errors.New("config: domain is required") }
	out, err := runDoctorCmd(t, load, fakeDoctorDeps(sameAddr), "--json")
	if got := exitcode.Status(err, nil); got != 1 {
		t.Fatalf("exit status = %d (err %v), want 1", got, err)
	}
	var rep doctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if rep.OK || len(rep.Checks) != 1 || rep.Checks[0].Name != "config" || rep.Checks[0].Status != doctorFail {
		t.Fatalf("report = %+v, want only a failed config check", rep)
	}
}

func TestDoctorDNSMismatchWarns(t *testing.T) {
	cfg := doctorConfig(t)
	lookup := func(host string) ([]string, error) {
		if host == cfg.Domain {
			return []string{"192.0.2.1"}, nil
		}
		return []string{"198.51.100.7"}, nil
	}
	out, err := runDoctorCmd(t, func() (*config.Config, error) { return cfg, nil }, fakeDoctorDeps(lookup), "--json")
	if err != nil {
		t.Fatalf("warnings must not fail the command: %v", err)
	}
	var rep doctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if c := findCheck(t, rep, "dns_apex"); c.Status != doctorOK {
		t.Errorf("dns_apex = %+v, want ok", c)
	}
	if c := findCheck(t, rep, "dns_wildcard"); c.Status != doctorWarn || c.Hint == "" {
		t.Errorf("dns_wildcard = %+v, want warn with a hint", c)
	}
	if c := findCheck(t, rep, "listen"); c.Status != doctorOK || c.Message != "server is running" {
		t.Errorf("listen = %+v, want ok, server is running", c)
	}
	if !rep.OK {
		t.Error("ok = false, want true")
	}
}

func TestDoctorDNSFailAndListenFail(t *testing.T) {
	cfg := doctorConfig(t)
	deps := fakeDoctorDeps(func(string) ([]string, error) { return nil, errors.New("no such host") })
	deps.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}
	deps.listen = func(string) (io.Closer, error) { return nil, errors.New("address already in use") }
	out, err := runDoctorCmd(t, func() (*config.Config, error) { return cfg, nil }, deps)
	if got := exitcode.Status(err, nil); got != 1 {
		t.Fatalf("exit status = %d, want 1", got)
	}
	for _, want := range []string{"CHECK", "dns_apex", "dns_wildcard", "healthz", "server not reachable", "address already in use"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
}

func selfSigned(t *testing.T, dir string, names ...string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestDoctorTLSFiles(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.TLS.Mode = config.TLSModeFiles
	cfg.TLS.CertFile, cfg.TLS.KeyFile = selfSigned(t, t.TempDir(), cfg.Domain, "*."+cfg.Domain)
	deps := fakeDoctorDeps(sameAddr)
	if c := checkTLS(deps, cfg); c.Status != doctorOK {
		t.Fatalf("tls = %+v, want ok", c)
	}

	// A certificate for another name fails.
	cfg.TLS.CertFile, cfg.TLS.KeyFile = selfSigned(t, t.TempDir(), "other.example.org")
	if c := checkTLS(deps, cfg); c.Status != doctorFail || c.Hint == "" {
		t.Fatalf("tls with a foreign certificate = %+v, want fail", c)
	}

	// An apex-only certificate does not cover the wildcard.
	cfg.TLS.CertFile, cfg.TLS.KeyFile = selfSigned(t, t.TempDir(), cfg.Domain)
	if c := checkTLS(deps, cfg); c.Status != doctorFail || !strings.Contains(c.Message, "*.") {
		t.Fatalf("tls with an apex-only certificate = %+v, want fail about the wildcard", c)
	}

	// An expired certificate fails.
	cfg.TLS.CertFile, cfg.TLS.KeyFile = selfSigned(t, t.TempDir(), cfg.Domain, "*."+cfg.Domain)
	deps.now = func() time.Time { return time.Now().Add(365 * 24 * time.Hour) }
	if c := checkTLS(deps, cfg); c.Status != doctorFail || !strings.Contains(c.Message, "expired") {
		t.Fatalf("tls with an expired certificate = %+v, want fail", c)
	}
}

func TestDoctorTLSModes(t *testing.T) {
	cfg := doctorConfig(t)
	if c := checkTLS(fakeDoctorDeps(sameAddr), cfg); c.Status != doctorOK {
		t.Errorf("acme with email = %+v, want ok", c)
	}
	cfg.TLS.ACME.Email = ""
	if c := checkTLS(fakeDoctorDeps(sameAddr), cfg); c.Status != doctorWarn {
		t.Errorf("acme without email = %+v, want warn", c)
	}
	cfg.TLS.Mode = config.TLSModeOff
	if c := checkTLS(fakeDoctorDeps(sameAddr), cfg); c.Status != doctorWarn {
		t.Errorf("off = %+v, want warn", c)
	}
}

func TestDoctorJSONShape(t *testing.T) {
	cfg := doctorConfig(t)
	out, err := runDoctorCmd(t, func() (*config.Config, error) { return cfg, nil }, fakeDoctorDeps(sameAddr), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Checks []map[string]any `json:"checks"`
		OK     *bool            `json:"ok"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if raw.OK == nil || !*raw.OK {
		t.Fatalf("ok = %v, want true:\n%s", raw.OK, out)
	}
	var names []string
	for _, c := range raw.Checks {
		for _, k := range []string{"name", "status", "message", "hint"} {
			if _, ok := c[k]; !ok {
				t.Errorf("check %v lacks %q", c, k)
			}
		}
		names = append(names, c["name"].(string))
	}
	if got, want := strings.Join(names, ","), "config,data_dir,dns_apex,dns_wildcard,healthz,listen,tls"; got != want {
		t.Errorf("checks = %s, want %s", got, want)
	}
}

func TestDoctorDataDir(t *testing.T) {
	dir := t.TempDir()
	if c := checkDataDir(dir); c.Status != doctorOK {
		t.Errorf("existing dir = %+v, want ok", c)
	}
	if c := checkDataDir(filepath.Join(dir, "new")); c.Status != doctorOK {
		t.Errorf("missing dir with a parent = %+v, want ok", c)
	}
	if c := checkDataDir(filepath.Join(dir, "a", "b")); c.Status != doctorFail {
		t.Errorf("missing dir and parent = %+v, want fail", c)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("doctor left files behind: %v", entries)
	}
}
