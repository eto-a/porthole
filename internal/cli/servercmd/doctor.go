// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/config"
)

// Statuses of a doctor check.
const (
	doctorOK   = "ok"
	doctorWarn = "warn"
	doctorFail = "fail"
)

const (
	doctorTimeout    = 5 * time.Second
	doctorCertWarn   = 14 * 24 * time.Hour
	doctorMaxHealthz = 1 << 10
)

// doctorCheck is one line of the report.
type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// doctorReport is the --json document.
type doctorReport struct {
	Checks []doctorCheck `json:"checks"`
	OK     bool          `json:"ok"`
}

// doctorDeps holds everything doctor takes from the outside world, so that tests do not touch the network.
type doctorDeps struct {
	// lookup resolves a host name to its addresses.
	lookup func(ctx context.Context, host string) ([]string, error)
	// client performs the healthz request.
	client *http.Client
	// listen binds addr and returns the listener to close at once.
	listen func(addr string) (io.Closer, error)
	// now is the current time.
	now func() time.Time
}

func defaultDoctorDeps() doctorDeps {
	return doctorDeps{
		lookup: func(ctx context.Context, host string) ([]string, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(addrs))
			for _, a := range addrs {
				out = append(out, a.IP.String())
			}
			return out, nil
		},
		client: &http.Client{Timeout: doctorTimeout},
		listen: func(addr string) (io.Closer, error) { return net.Listen("tcp", addr) },
		now:    time.Now,
	}
}

// NewDoctor returns the `doctor` command: a read-only diagnosis of a server installation (configuration, data
// directory, DNS, ports, health endpoint, certificates). It changes nothing and exits with status 1 when a check fails.
func NewDoctor(load func() (*config.Config, error)) *cobra.Command {
	return newDoctor(load, defaultDoctorDeps())
}

func newDoctor(load func() (*config.Config, error), deps doctorDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose the server installation (read-only)",
		Long: "Checks the configuration, the data directory, the DNS records, the listen ports, the health endpoint and the\n" +
			"certificates, and prints a hint for everything that is not right. It changes nothing. Run it as the service\n" +
			"user (sudo -u porthole portholed doctor) to test the permissions that matter.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep := runDoctor(cmd.Context(), load, deps)
			if jsonout.Enabled(cmd) {
				if err := jsonout.Write(cmd.OutOrStdout(), rep); err != nil {
					return err
				}
			} else {
				writeDoctorTable(cmd.OutOrStdout(), rep)
			}
			if !rep.OK {
				return &exitcode.Error{Code: exitcode.General, Err: errors.New("doctor: some checks failed"), Quiet: true}
			}
			return nil
		},
	}
}

func runDoctor(ctx context.Context, load func() (*config.Config, error), deps doctorDeps) doctorReport {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := load()
	if err != nil {
		return newDoctorReport([]doctorCheck{{
			Name: "config", Status: doctorFail, Message: err.Error(),
			Hint: "fix the configuration file (see docs/server.md); the other checks need it and were skipped",
		}})
	}
	checks := []doctorCheck{{Name: "config", Status: doctorOK, Message: "configuration is valid"}}
	checks = append(checks, checkDataDir(cfg.DataDir))
	checks = append(checks, checkDNS(ctx, deps, cfg.Domain)...)
	health := checkHealthz(ctx, deps, cfg)
	checks = append(checks, health, checkListen(deps, cfg, health.Status == doctorOK), checkTLS(deps, cfg))
	return newDoctorReport(checks)
}

func newDoctorReport(checks []doctorCheck) doctorReport {
	rep := doctorReport{Checks: checks, OK: true}
	for _, c := range checks {
		if c.Status == doctorFail {
			rep.OK = false
		}
	}
	return rep
}

func writeDoctorTable(w io.Writer, rep doctorReport) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tSTATUS\tMESSAGE")
	for _, c := range rep.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, c.Status, c.Message)
	}
	_ = tw.Flush()
	var hints []doctorCheck
	for _, c := range rep.Checks {
		if c.Hint != "" && c.Status != doctorOK {
			hints = append(hints, c)
		}
	}
	if len(hints) > 0 {
		fmt.Fprintln(w)
		for _, c := range hints {
			fmt.Fprintf(w, "%s: %s\n", c.Name, c.Hint)
		}
	}
}

// checkDataDir checks that the data directory, or its parent when it is not created yet, can be written to.
func checkDataDir(dir string) doctorCheck {
	c := doctorCheck{Name: "data_dir"}
	target := dir
	st, err := os.Stat(dir)
	switch {
	case err == nil && !st.IsDir():
		c.Status, c.Message, c.Hint = doctorFail, dir+" is not a directory", "point data_dir at a directory"
		return c
	case err != nil && errors.Is(err, os.ErrNotExist):
		target = filepath.Dir(dir)
		if pst, perr := os.Stat(target); perr != nil || !pst.IsDir() {
			c.Status, c.Message = doctorFail, fmt.Sprintf("%s and its parent do not exist", dir)
			c.Hint = "create the directory, owned by the service user: install -d -o porthole " + dir
			return c
		}
	case err != nil:
		c.Status, c.Message, c.Hint = doctorFail, err.Error(), "check the permissions of "+dir
		return c
	}
	f, err := os.CreateTemp(target, ".porthole-doctor-*")
	if err != nil {
		c.Status, c.Message = doctorWarn, fmt.Sprintf("%s is not writable by this user: %v", target, err)
		c.Hint = "run as the service user (sudo -u porthole portholed doctor); the server needs write access to the data directory"
		return c
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	if target != dir {
		c.Status, c.Message = doctorOK, dir+" does not exist yet, its parent is writable (the server creates it)"
		return c
	}
	c.Status, c.Message = doctorOK, dir+" exists and is writable"
	return c
}

func checkDNS(ctx context.Context, deps doctorDeps, domain string) []doctorCheck {
	var suffix [4]byte
	_, _ = rand.Read(suffix[:])
	wildHost := "doctor-" + hex.EncodeToString(suffix[:]) + "." + domain
	apex := doctorCheck{Name: "dns_apex"}
	wild := doctorCheck{Name: "dns_wildcard"}

	resolve := func(host string) ([]string, error) {
		cctx, cancel := context.WithTimeout(ctx, doctorTimeout)
		defer cancel()
		addrs, err := deps.lookup(cctx, host)
		if err == nil && len(addrs) == 0 {
			err = errors.New("no addresses")
		}
		slices.Sort(addrs)
		return slices.Compact(addrs), err
	}
	apexAddrs, aerr := resolve(domain)
	wildAddrs, werr := resolve(wildHost)

	if aerr != nil {
		apex.Status, apex.Message = doctorFail, fmt.Sprintf("%s does not resolve: %v", domain, aerr)
		apex.Hint = "add an A/AAAA record for " + domain + " pointing at this server (a wildcard record does not cover it)"
	} else {
		apex.Status, apex.Message = doctorOK, fmt.Sprintf("%s -> %s", domain, strings.Join(apexAddrs, ", "))
	}
	switch {
	case werr != nil:
		wild.Status, wild.Message = doctorFail, fmt.Sprintf("%s does not resolve: %v", wildHost, werr)
		wild.Hint = "add a wildcard record *." + domain + " pointing at this server"
	case aerr == nil && !slices.Equal(apexAddrs, wildAddrs):
		wild.Status = doctorWarn
		wild.Message = fmt.Sprintf("%s -> %s, differs from %s", wildHost, strings.Join(wildAddrs, ", "), strings.Join(apexAddrs, ", "))
		wild.Hint = "the wildcard record *." + domain + " points elsewhere than " + domain + "; make both point at this server"
	default:
		wild.Status, wild.Message = doctorOK, fmt.Sprintf("%s -> %s", wildHost, strings.Join(wildAddrs, ", "))
	}
	return []doctorCheck{apex, wild}
}

// healthzURL is the address of the health endpoint as clients see it.
func healthzURL(cfg *config.Config) string {
	base := cfg.ClientURL()
	if base == "" {
		scheme := cfg.PublicScheme
		if scheme == "" {
			scheme = "https"
		}
		base = scheme + "://" + cfg.Domain
		if cfg.PublicPort != 0 {
			base += fmt.Sprintf(":%d", cfg.PublicPort)
		}
	}
	return base + "/healthz"
}

func isTLSError(err error) bool {
	var (
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		certInvalid x509.CertificateInvalidError
		verifyErr   *tls.CertificateVerificationError
		recordErr   tls.RecordHeaderError
	)
	return errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &certInvalid) ||
		errors.As(err, &verifyErr) || errors.As(err, &recordErr) || strings.Contains(err.Error(), "tls:")
}

func checkHealthz(ctx context.Context, deps doctorDeps, cfg *config.Config) doctorCheck {
	c := doctorCheck{Name: "healthz"}
	url := healthzURL(cfg)
	cctx, cancel := context.WithTimeout(ctx, doctorTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		c.Status, c.Message = doctorWarn, err.Error()
		return c
	}
	resp, err := deps.client.Do(req)
	if err != nil {
		if isTLSError(err) {
			c.Status, c.Message = doctorWarn, "TLS error: "+err.Error()
			c.Hint = "the certificate may not be issued yet (acme: it is ordered at the first request, see docs/troubleshooting.md) or the tls.mode files do not match " + cfg.Domain
			return c
		}
		c.Status, c.Message = doctorWarn, "server not reachable from here: "+err.Error()
		c.Hint = "start the server, or check the firewall and that " + cfg.Domain + " resolves to this host"
		return c
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, doctorMaxHealthz))
	if resp.StatusCode != http.StatusOK {
		c.Status, c.Message = doctorWarn, fmt.Sprintf("%s answered %s", url, resp.Status)
		c.Hint = "something other than portholed answers on " + cfg.Domain + ", or a proxy in front of it is misconfigured"
		return c
	}
	c.Status, c.Message = doctorOK, url+" answered 200"
	return c
}

// checkListen tries to bind every address the server would open. When the server answers healthz, it already holds them.
func checkListen(deps doctorDeps, cfg *config.Config, running bool) doctorCheck {
	c := doctorCheck{Name: "listen"}
	if running {
		c.Status, c.Message = doctorOK, "server is running"
		return c
	}
	var addrs []string
	for _, a := range []string{cfg.Listen, cfg.HTTPListenAddr(), cfg.SSHGateway.Listen} {
		if a != "" && !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	for _, a := range addrs {
		l, err := deps.listen(a)
		if err != nil {
			c.Status, c.Message = doctorFail, fmt.Sprintf("cannot listen on %s: %v", a, err)
			c.Hint = "the port is in use by another program, or ports below 1024 need root or CAP_NET_BIND_SERVICE"
			return c
		}
		_ = l.Close()
	}
	c.Status, c.Message = doctorOK, "can listen on "+strings.Join(addrs, ", ")
	return c
}

func checkTLS(deps doctorDeps, cfg *config.Config) doctorCheck {
	c := doctorCheck{Name: "tls"}
	switch cfg.TLS.EffectiveMode() {
	case config.TLSModeOff:
		c.Status, c.Message = doctorWarn, "TLS is off"
		c.Hint = "put a TLS-terminating proxy in front of the server"
	case config.TLSModeACME:
		if cfg.TLS.ACME.Email == "" {
			c.Status, c.Message = doctorWarn, "certificates are obtained on demand, but tls.acme.email is empty"
			c.Hint = "set tls.acme.email so the CA can warn you about problems"
		} else {
			c.Status, c.Message = doctorOK, "certificates are obtained on demand"
		}
	default:
		return checkTLSFiles(deps, cfg)
	}
	return c
}

func checkTLSFiles(deps doctorDeps, cfg *config.Config) doctorCheck {
	c := doctorCheck{Name: "tls", Status: doctorFail}
	pair, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		c.Message, c.Hint = err.Error(), "check that tls.cert_file and tls.key_file exist, are readable by the service user and belong together"
		return c
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		c.Message, c.Hint = "parse certificate: "+err.Error(), "tls.cert_file must start with the server certificate in PEM"
		return c
	}
	now := deps.now()
	switch {
	case now.After(leaf.NotAfter):
		c.Message, c.Hint = "certificate expired on "+leaf.NotAfter.UTC().Format(time.DateOnly), "renew the certificate and reload the server"
		return c
	case now.Before(leaf.NotBefore):
		c.Message, c.Hint = "certificate is not valid before "+leaf.NotBefore.UTC().Format(time.DateOnly), "check the clock of this host and the certificate"
		return c
	}
	for _, host := range []string{cfg.Domain, "probe." + cfg.Domain} {
		if err := leaf.VerifyHostname(host); err != nil {
			c.Message = "certificate does not cover " + strings.Replace(host, "probe.", "*.", 1) + ": " + err.Error()
			c.Hint = "the certificate must list both " + cfg.Domain + " and *." + cfg.Domain
			return c
		}
	}
	if leaf.NotAfter.Sub(now) < doctorCertWarn {
		c.Status = doctorWarn
		c.Message = "certificate expires on " + leaf.NotAfter.UTC().Format(time.DateOnly)
		c.Hint = "renew the certificate soon"
		return c
	}
	c.Status = doctorOK
	c.Message = "certificate covers the domain and its wildcard, valid until " + leaf.NotAfter.UTC().Format(time.DateOnly)
	return c
}
