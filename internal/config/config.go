// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates the portholed server configuration (DESIGN.md §3.9).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CurrentVersion is the config schema version understood by this build.
const CurrentVersion = 1

// Config is the server configuration.
type Config struct {
	Version int `yaml:"version"`

	// Domain is the base domain. The control endpoint lives at https://<Domain>/..., HTTP tunnels at
	// https://<label>.<Domain>, TCP tunnels at <Domain>:<port>.
	Domain string `yaml:"domain"`

	// Listen is the address of the HTTP(S) listener, e.g. ":443".
	Listen string `yaml:"listen"`

	// HTTPListen is the address of the plain-HTTP listener that answers ACME HTTP-01 challenges and redirects
	// everything else to https:// (ADR 0004). Unset means ":80" in TLS mode "acme" and no listener in the other
	// modes; an explicit empty string disables it. It is an error in mode "off", where Listen is already plain HTTP.
	HTTPListen *string `yaml:"http_listen"`

	// MetricsListen is the address of the listener that serves Prometheus metrics at /metrics and the Go profiler
	// at /debug/pprof/. Empty (the default) disables it. Use a loopback address such as "127.0.0.1:9090": the
	// endpoints are unauthenticated.
	MetricsListen string `yaml:"metrics_listen"`

	TLS TLS `yaml:"tls"`

	// PublicScheme is the scheme used in public HTTP tunnel URLs ("https" or "http").
	// Defaults to "https"; set "http" only for local development.
	PublicScheme string `yaml:"public_scheme"`

	// ServerURL is the address clients connect to ("porthole login <server_url> <token>"), for example
	// "https://tun.example.com". Optional: when empty it is derived from PublicScheme, Domain and PublicPort.
	// Needed when the control endpoint is reached differently from the tunnel hosts, for example over HTTPS
	// behind a TLS proxy while tunnels are plain HTTP. Absolute http(s) URL without path, query or fragment.
	ServerURL string `yaml:"server_url"`

	// PublicPort is appended to public HTTP URLs when non-zero (e.g. 8080 in development).
	PublicPort int `yaml:"public_port"`

	// TCPPortRange is the inclusive range of public ports for TCP tunnels, "20000-29999".
	TCPPortRange string `yaml:"tcp_port_range"`

	// TCPBindHost is the address TCP tunnel listeners bind to (default all interfaces).
	TCPBindHost string `yaml:"tcp_bind_host"`

	// SSHGateway configures the SSH jump-host gateway (ADR 0003).
	SSHGateway SSHGateway `yaml:"ssh_gateway"`

	// DataDir holds the SQLite database.
	DataDir string `yaml:"data_dir"`

	// AdminSocket is the unix socket of the admin API (mode 0600, access is the permission). Empty means
	// <data_dir>/admin.sock; "-" turns the socket off. Not served on Windows.
	AdminSocket string `yaml:"admin_socket"`

	// TrustProxyHeaders makes the server take visitor addresses from X-Forwarded-For.
	// Enable only when portholed runs behind a reverse proxy you control.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`

	// ProxyProtocol makes the HTTP(S) listener and the SSH gateway accept PROXY protocol v1/v2 headers from the
	// peers in TrustedProxies, so that per-IP limits, the failure limiter and the logs see the real visitor address
	// when a proxy forwards raw TCP (for example Traefik with TLS passthrough). A peer in TrustedProxies must send a
	// header; any other peer must not (its connection is refused if it does). Requires TrustedProxies.
	ProxyProtocol bool `yaml:"proxy_protocol"`

	// ProxyProtocolHTTP extends ProxyProtocol to the plain-HTTP listener (http_listen). Off by default because
	// proxies usually cannot add PROXY headers to HTTP routers (Traefik can only do it for TCP services).
	ProxyProtocolHTTP bool `yaml:"proxy_protocol_http"`

	// TrustedProxies lists the IP addresses and CIDR ranges of the proxies allowed to send PROXY protocol headers.
	TrustedProxies []string `yaml:"trusted_proxies"`

	// MaxTunnelsPerClient applies to tokens without their own limit.
	MaxTunnelsPerClient int `yaml:"max_tunnels_per_client"`

	// ShutdownGrace bounds graceful shutdown.
	ShutdownGrace time.Duration `yaml:"shutdown_grace"`

	// Traffic sizes the in-memory request and connection journals (ADR 0005).
	Traffic Traffic `yaml:"traffic"`

	// Audit configures the admin audit log kept in the database.
	Audit Audit `yaml:"audit"`
}

// DefaultAuditMaxRows is how many audit rows are kept by default.
const DefaultAuditMaxRows = 100_000

// Audit configures the retention of the admin audit log.
type Audit struct {
	// MaxRows is the number of newest audit rows kept; older rows are deleted. 0 means DefaultAuditMaxRows.
	MaxRows int `yaml:"max_rows"`
}

// DefaultTrafficMax is the default size of each traffic journal.
const DefaultTrafficMax = 10000

// Traffic configures the in-memory ring buffers of the traffic journal. They are lost on restart.
type Traffic struct {
	// MaxRequests is the number of HTTP requests kept; 0 turns the request log off.
	MaxRequests int `yaml:"max_requests"`

	// MaxConns is the number of TCP and SSH connections kept; 0 turns the connection log off.
	MaxConns int `yaml:"max_conns"`

	// AllowInspect lets clients ask for body inspection of an HTTP tunnel (porthole http --inspect); when false
	// such a register request is refused.
	AllowInspect bool `yaml:"allow_inspect"`

	// MaxDetailBytes bounds the memory held by stored request and response bodies and headers of inspected
	// requests; the oldest details are dropped first. 0 stores no details.
	MaxDetailBytes int64 `yaml:"max_detail_bytes"`
}

// DefaultMaxDetailBytes is the default budget of inspected request details: 64 MiB.
const DefaultMaxDetailBytes = 64 << 20

// TLS modes (ADR 0004).
const (
	// TLSModeACME obtains and renews one certificate per host name on demand via ACME.
	TLSModeACME = "acme"
	// TLSModeFiles serves the certificate from CertFile/KeyFile (for example a wildcard from certbot).
	TLSModeFiles = "files"
	// TLSModeOff serves plain HTTP, for use behind a proxy that terminates TLS.
	TLSModeOff = "off"
)

// DefaultACMECA is the ACME directory used when TLS.ACME.CA is empty (Let's Encrypt production).
const DefaultACMECA = "https://acme-v02.api.letsencrypt.org/directory"

// TLS configures how the HTTP listener gets certificates.
type TLS struct {
	// Mode is "acme", "files" or "off". Empty means "files" when CertFile is set and "acme" otherwise.
	Mode string `yaml:"mode"`

	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	ACME ACME `yaml:"acme"`
}

// ACME configures the "acme" TLS mode.
type ACME struct {
	// Email is the optional ACME account contact address (expiry notices from the CA).
	Email string `yaml:"email"`

	// CA is the ACME directory URL; empty means Let's Encrypt production (DefaultACMECA).
	CA string `yaml:"ca"`
}

// DefaultSSHMaxConnsPerTunnel is the default for SSHGateway.MaxConnsPerTunnel.
const DefaultSSHMaxConnsPerTunnel = 256

// SSHGateway configures the SSH gateway: a listener that forwards direct-tcpip channels to "ssh" tunnels.
type SSHGateway struct {
	// Listen is the gateway address, e.g. ":2222". Empty disables the gateway.
	Listen string `yaml:"listen"`

	// MaxConnsPerTunnel limits concurrent channels per ssh tunnel.
	MaxConnsPerTunnel int `yaml:"max_conns_per_tunnel"`
}

// Enabled reports whether the gateway is configured.
func (g SSHGateway) Enabled() bool { return g.Listen != "" }

// Port returns the port of Listen, or 0 when the gateway is disabled or Listen has no numeric port.
func (g SSHGateway) Port() int {
	_, p, err := net.SplitHostPort(g.Listen)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return n
}

// EffectiveMode resolves an empty Mode: "files" when a certificate file is set, "acme" otherwise.
func (t TLS) EffectiveMode() string {
	switch {
	case t.Mode != "":
		return t.Mode
	case t.CertFile != "":
		return TLSModeFiles
	default:
		return TLSModeACME
	}
}

// Enabled reports whether the server terminates TLS itself.
func (t TLS) Enabled() bool { return t.EffectiveMode() != TLSModeOff }

// CAURL returns the ACME directory URL with the default applied.
func (a ACME) CAURL() string {
	if a.CA == "" {
		return DefaultACMECA
	}
	return a.CA
}

// HTTPListenAddr returns the address of the plain-HTTP (challenge and redirect) listener, or "" when none runs.
func (c *Config) HTTPListenAddr() string {
	if c.HTTPListen != nil {
		return *c.HTTPListen
	}
	if c.TLS.EffectiveMode() == TLSModeACME {
		return ":80"
	}
	return ""
}

// Default returns a configuration with all defaults applied and no domain.
func Default() *Config {
	return &Config{
		Version:             CurrentVersion,
		Listen:              ":443",
		PublicScheme:        "https",
		TCPPortRange:        "20000-29999",
		SSHGateway:          SSHGateway{MaxConnsPerTunnel: DefaultSSHMaxConnsPerTunnel},
		DataDir:             "/var/lib/porthole",
		MaxTunnelsPerClient: 10,
		ShutdownGrace:       10 * time.Second,
		Audit:               Audit{MaxRows: DefaultAuditMaxRows},
		Traffic:             Traffic{MaxRequests: DefaultTrafficMax, MaxConns: DefaultTrafficMax, AllowInspect: true, MaxDetailBytes: DefaultMaxDetailBytes},
	}
}

// Load reads the YAML file at path (if path is non-empty), applies PORTHOLED_* environment overrides and
// validates the result. Unknown YAML keys are an error.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	if err := c.applyEnv(os.LookupEnv); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyEnv(lookup func(string) (string, bool)) error {
	str := map[string]*string{
		"PORTHOLED_DOMAIN":         &c.Domain,
		"PORTHOLED_LISTEN":         &c.Listen,
		"PORTHOLED_TLS_CERT_FILE":  &c.TLS.CertFile,
		"PORTHOLED_TLS_KEY_FILE":   &c.TLS.KeyFile,
		"PORTHOLED_TLS_MODE":       &c.TLS.Mode,
		"PORTHOLED_ACME_EMAIL":     &c.TLS.ACME.Email,
		"PORTHOLED_ACME_CA":        &c.TLS.ACME.CA,
		"PORTHOLED_PUBLIC_SCHEME":  &c.PublicScheme,
		"PORTHOLED_SERVER_URL":     &c.ServerURL,
		"PORTHOLED_TCP_PORT_RANGE": &c.TCPPortRange,
		"PORTHOLED_TCP_BIND_HOST":  &c.TCPBindHost,
		"PORTHOLED_DATA_DIR":       &c.DataDir,
		"PORTHOLED_ADMIN_SOCKET":   &c.AdminSocket,
		"PORTHOLED_SSH_LISTEN":     &c.SSHGateway.Listen,
		"PORTHOLED_METRICS_LISTEN": &c.MetricsListen,
	}
	for k, p := range str {
		if v, ok := lookup(k); ok {
			*p = v
		}
	}
	ints := map[string]*int{
		"PORTHOLED_PUBLIC_PORT":            &c.PublicPort,
		"PORTHOLED_MAX_TUNNELS_PER_CLIENT": &c.MaxTunnelsPerClient,
		"PORTHOLED_TRAFFIC_MAX_REQUESTS":   &c.Traffic.MaxRequests,
		"PORTHOLED_TRAFFIC_MAX_CONNS":      &c.Traffic.MaxConns,
		"PORTHOLED_AUDIT_MAX_ROWS":         &c.Audit.MaxRows,
	}
	for k, p := range ints {
		if v, ok := lookup(k); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("config: %s: %w", k, err)
			}
			*p = n
		}
	}
	if v, ok := lookup("PORTHOLED_HTTP_LISTEN"); ok {
		c.HTTPListen = &v
	}
	if v, ok := lookup("PORTHOLED_TRUST_PROXY_HEADERS"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: PORTHOLED_TRUST_PROXY_HEADERS: %w", err)
		}
		c.TrustProxyHeaders = b
	}
	for k, p := range map[string]*bool{
		"PORTHOLED_PROXY_PROTOCOL":      &c.ProxyProtocol,
		"PORTHOLED_PROXY_PROTOCOL_HTTP": &c.ProxyProtocolHTTP,
	} {
		if v, ok := lookup(k); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("config: %s: %w", k, err)
			}
			*p = b
		}
	}
	if v, ok := lookup("PORTHOLED_TRUSTED_PROXIES"); ok {
		c.TrustedProxies = nil
		for _, e := range strings.Split(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				c.TrustedProxies = append(c.TrustedProxies, e)
			}
		}
	}
	if v, ok := lookup("PORTHOLED_TRAFFIC_ALLOW_INSPECT"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: PORTHOLED_TRAFFIC_ALLOW_INSPECT: %w", err)
		}
		c.Traffic.AllowInspect = b
	}
	if v, ok := lookup("PORTHOLED_TRAFFIC_MAX_DETAIL_BYTES"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("config: PORTHOLED_TRAFFIC_MAX_DETAIL_BYTES: %w", err)
		}
		c.Traffic.MaxDetailBytes = n
	}
	return nil
}

// Validate checks the configuration for consistency.
func (c *Config) Validate() error {
	var errs []error
	if c.Version != CurrentVersion {
		errs = append(errs, fmt.Errorf("version: got %d, this build supports %d", c.Version, CurrentVersion))
	}
	if c.Domain == "" {
		errs = append(errs, errors.New("domain: required"))
	} else if strings.ContainsAny(c.Domain, "/: ") || strings.HasPrefix(c.Domain, ".") {
		errs = append(errs, fmt.Errorf("domain: %q is not a bare host name", c.Domain))
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, fmt.Errorf("listen: %w", err))
	}
	errs = append(errs, c.validateTLS()...)
	if c.PublicScheme != "https" && c.PublicScheme != "http" {
		errs = append(errs, fmt.Errorf("public_scheme: %q, want https or http", c.PublicScheme))
	}
	if err := validateServerURL(c.ServerURL); err != nil {
		errs = append(errs, err)
	}
	if c.PublicPort < 0 || c.PublicPort > 65535 {
		errs = append(errs, fmt.Errorf("public_port: %d out of range", c.PublicPort))
	}
	if _, _, err := c.PortRange(); err != nil {
		errs = append(errs, err)
	}
	if c.SSHGateway.Enabled() {
		if _, p, err := net.SplitHostPort(c.SSHGateway.Listen); err != nil {
			errs = append(errs, fmt.Errorf("ssh_gateway.listen: %w", err))
		} else if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			errs = append(errs, fmt.Errorf("ssh_gateway.listen: %q needs a numeric port 1-65535", c.SSHGateway.Listen))
		}
	}
	if c.MetricsListen != "" {
		if _, _, err := net.SplitHostPort(c.MetricsListen); err != nil {
			errs = append(errs, fmt.Errorf("metrics_listen: %w", err))
		}
	}
	errs = append(errs, c.validateProxyProtocol()...)
	if c.SSHGateway.MaxConnsPerTunnel < 0 {
		errs = append(errs, errors.New("ssh_gateway.max_conns_per_tunnel: must not be negative"))
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir: required"))
	}
	if c.MaxTunnelsPerClient <= 0 {
		errs = append(errs, errors.New("max_tunnels_per_client: must be positive"))
	}
	if c.ShutdownGrace < 0 {
		errs = append(errs, errors.New("shutdown_grace: must not be negative"))
	}
	if c.Audit.MaxRows < 0 {
		errs = append(errs, errors.New("audit.max_rows: must not be negative"))
	}
	if c.Traffic.MaxRequests < 0 {
		errs = append(errs, errors.New("traffic.max_requests: must not be negative"))
	}
	if c.Traffic.MaxConns < 0 {
		errs = append(errs, errors.New("traffic.max_conns: must not be negative"))
	}
	if c.Traffic.MaxDetailBytes < 0 {
		errs = append(errs, errors.New("traffic.max_detail_bytes: must not be negative"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

func (c *Config) validateProxyProtocol() []error {
	var errs []error
	for _, e := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(e); err == nil {
			continue
		}
		if a, err := netip.ParseAddr(e); err != nil || a.Zone() != "" {
			errs = append(errs, fmt.Errorf("trusted_proxies: %q is not an IP address or CIDR range", e))
		}
	}
	if c.ProxyProtocol && len(c.TrustedProxies) == 0 {
		errs = append(errs, errors.New("proxy_protocol: needs trusted_proxies (the proxies allowed to send PROXY headers)"))
	}
	if c.ProxyProtocolHTTP && !c.ProxyProtocol {
		errs = append(errs, errors.New("proxy_protocol_http: needs proxy_protocol"))
	}
	return errs
}

// validateServerURL accepts an empty value or an absolute http(s) URL with a host and nothing after it
// (a single trailing slash is allowed).
func validateServerURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("server_url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("server_url: %q, want an absolute http:// or https:// URL", s)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("server_url: %q must not have a path, query, fragment or user info", s)
	}
	return nil
}

// ClientURL returns the address clients should connect to: ServerURL without a trailing slash, or "" when
// ServerURL is not set.
func (c *Config) ClientURL() string { return strings.TrimSuffix(c.ServerURL, "/") }

func (c *Config) validateTLS() []error {
	var errs []error
	t := c.TLS
	if (t.CertFile == "") != (t.KeyFile == "") {
		errs = append(errs, errors.New("tls: cert_file and key_file must be set together"))
	}
	switch t.EffectiveMode() {
	case TLSModeFiles:
		if t.CertFile == "" {
			errs = append(errs, errors.New("tls.mode: files needs cert_file and key_file"))
		}
	case TLSModeACME, TLSModeOff:
		if t.CertFile != "" {
			errs = append(errs, fmt.Errorf("tls.mode: %s does not use cert_file/key_file; remove them or use mode files", t.EffectiveMode()))
		}
	default:
		errs = append(errs, fmt.Errorf("tls.mode: %q, want acme, files or off", t.Mode))
	}
	if t.EffectiveMode() != TLSModeACME && (t.ACME.Email != "" || t.ACME.CA != "") {
		errs = append(errs, errors.New("tls.acme: only valid with tls.mode acme"))
	}
	if t.ACME.CA != "" {
		if u, err := url.Parse(t.ACME.CA); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, fmt.Errorf("tls.acme.ca: %q is not an http(s) URL", t.ACME.CA))
		}
	}
	if a := c.HTTPListenAddr(); a != "" {
		if t.EffectiveMode() == TLSModeOff {
			errs = append(errs, errors.New("http_listen: not allowed with tls.mode off (listen is already plain HTTP)"))
		} else if _, _, err := net.SplitHostPort(a); err != nil {
			errs = append(errs, fmt.Errorf("http_listen: %w", err))
		}
	}
	return errs
}

// PortRange parses TCPPortRange.
func (c *Config) PortRange() (lo, hi int, err error) {
	a, b, ok := strings.Cut(c.TCPPortRange, "-")
	if ok {
		lo, err = strconv.Atoi(strings.TrimSpace(a))
		if err == nil {
			hi, err = strconv.Atoi(strings.TrimSpace(b))
		}
	}
	if !ok || err != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("tcp_port_range: %q, want \"LOW-HIGH\" within 1-65535", c.TCPPortRange)
	}
	return lo, hi, nil
}

// AdminSocketPath returns where the admin socket lives, or "" when it is turned off (admin_socket: "-").
func (c *Config) AdminSocketPath() string {
	switch c.AdminSocket {
	case "-":
		return ""
	case "":
		return filepath.Join(c.DataDir, "admin.sock")
	}
	return c.AdminSocket
}

// DBPath is the SQLite database location.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "porthole.db") }
