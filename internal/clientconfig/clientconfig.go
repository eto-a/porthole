// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package clientconfig loads and validates the client tunnels file (tunnels.yaml): a list of named tunnels that the
// porthole client daemon (or `porthole start`) keeps up. It converts the file to client.TunnelSpec values and
// computes the difference between two tunnel sets, which the daemon uses to apply a reload without touching
// tunnels that did not change.
//
// The file holds no credentials. The token lives in config.yaml (or a token file); a `token` key in the tunnels
// file is rejected so that the file can be committed and shared. Decoding is strict: unknown keys are errors.
package clientconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/proto"
)

const (
	// Version is the only supported value of the `version` key.
	Version = 1

	// MaxFileSize is the largest tunnels file Load accepts, in bytes.
	MaxFileSize = 64 << 10

	// Tunnel types accepted in the `type` key.
	TypeHTTP = "http"
	TypeTCP  = "tcp"
	TypeSSH  = "ssh"

	// DefaultSSHAddr is the local target of an ssh tunnel that has no addr.
	DefaultSSHAddr = client.DefaultSSHAddr
)

// File is a parsed tunnels file.
type File struct {
	// Version is the file format version; it must be Version.
	Version int `yaml:"version"`
	// Server optionally overrides the server URL of config.yaml.
	Server string `yaml:"server,omitempty"`
	// Tunnels maps the tunnel name (auth.ValidName) to its definition.
	Tunnels map[string]Tunnel `yaml:"tunnels"`
	// AllowRemote limits the local targets the server may ask this machine to expose (`porthole remote open`, an
	// agent's request_tunnel): a list of targets ("ssh", "3000", "host:port"), `none` or `any`. Nil (the key is
	// missing) allows only targets on this machine: loopback addresses, localhost and ssh. The server cannot widen it.
	AllowRemote *RemoteAllow `yaml:"allow_remote,omitempty"`
}

// Tunnel is one entry of the tunnels file.
type Tunnel struct {
	// Type is TypeHTTP, TypeTCP or TypeSSH.
	Type string `yaml:"type"`
	// Addr is the local target: "3000", ":3000" or "host:port". Required for http and tcp; ssh defaults to
	// DefaultSSHAddr. After Parse it is always normalized to "host:port".
	Addr string `yaml:"addr,omitempty"`
	// RemotePort is the requested public port (tcp, and ssh with PublicPort only); 0 lets the server choose.
	RemotePort int `yaml:"remote_port,omitempty"`
	// Private (ssh only) makes the SSH gateway require a porthole token to reach the tunnel.
	Private bool `yaml:"private,omitempty"`
	// Inspect (http only) stores request and response bodies up to 64 KiB, with headers, on the server for the
	// inspector and replay (porthole http --inspect).
	Inspect bool `yaml:"inspect,omitempty"`
	// PublicPort (ssh only) is the v0.1 mode: a public TCP port instead of the SSH gateway.
	PublicPort bool `yaml:"public_port,omitempty"`
	// Enabled is nil (meaning true) unless the file says otherwise.
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether the tunnel is enabled; a missing `enabled` key means true.
func (t Tunnel) IsEnabled() bool { return t.Enabled == nil || *t.Enabled }

// Load reads and parses the tunnels file at path. The file may not exceed MaxFileSize. A missing file is reported
// as an error wrapping fs.ErrNotExist, so callers can tell it apart.
func Load(path string) (*File, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read tunnels file: %w", err)
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read tunnels file %s: %w", path, err)
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("tunnels file %s is larger than %d bytes", path, MaxFileSize)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("tunnels file %s: %w", path, err)
	}
	return f, nil
}

// Parse decodes and validates tunnels file content. Unknown keys, a missing or unsupported version, an empty
// document and more than one YAML document are errors. A file with `version: 1` and no tunnels is valid.
// Validation problems of all tunnels are collected and returned together (errors.Join). On success the tunnel
// addresses and the server URL are normalized in place.
func Parse(data []byte) (*File, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("file is larger than %d bytes", MaxFileSize)
	}
	if err := rejectToken(data); err != nil {
		return nil, err
	}
	if err := rejectNullAllowRemote(data); err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("file is empty: expected at least \"version: 1\"")
		}
		return nil, fmt.Errorf("parse: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("parse: more than one YAML document")
		}
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// rejectToken gives a friendly message when the file carries a credential. Strict decoding would reject the key
// as well, but with a generic "field token not found" error.
func rejectToken(data []byte) error {
	var probe struct {
		Token   yaml.Node `yaml:"token"`
		Tunnels map[string]struct {
			Token yaml.Node `yaml:"token"`
		} `yaml:"tunnels"`
	}
	// Errors are ignored on purpose: the strict decode that follows reports malformed input.
	_ = yaml.Unmarshal(data, &probe)
	const msg = "token is not allowed in the tunnels file; use config.yaml or token_file"
	if probe.Token.Kind != 0 {
		return errors.New(msg)
	}
	for _, name := range sortedKeys(probe.Tunnels) {
		if probe.Tunnels[name].Token.Kind != 0 {
			return fmt.Errorf("tunnel %q: %s", name, msg)
		}
	}
	return nil
}

// rejectNullAllowRemote turns `allow_remote:` without a value (also null and ~) into an error. yaml.v3 does not call
// UnmarshalYAML for a null node and leaves the field nil, which would silently mean "the default policy" for an
// operator who emptied the list (or commented out all its items) to say "nothing".
func rejectNullAllowRemote(data []byte) error {
	var probe struct {
		AllowRemote yaml.Node `yaml:"allow_remote"`
	}
	// Errors are ignored on purpose: the strict decode that follows reports malformed input.
	_ = yaml.Unmarshal(data, &probe)
	if probe.AllowRemote.Kind == yaml.ScalarNode && probe.AllowRemote.Tag == "!!null" {
		return fmt.Errorf("line %d: allow_remote has no value: write a list of targets, none or any (or remove the key)", probe.AllowRemote.Line)
	}
	return nil
}

func (f *File) validate() error {
	if f.Version != Version {
		if f.Version == 0 {
			return fmt.Errorf("missing version: add \"version: %d\"", Version)
		}
		return fmt.Errorf("unsupported version %d (this client reads version %d)", f.Version, Version)
	}
	var errs []error
	if server, err := normalizeServer(f.Server); err != nil {
		errs = append(errs, fmt.Errorf("server: %w", err))
	} else {
		f.Server = server
	}
	for _, name := range sortedKeys(f.Tunnels) {
		t := f.Tunnels[name]
		spec, err := t.spec(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		t.Addr = spec.LocalAddr
		f.Tunnels[name] = t
	}
	return errors.Join(errs...)
}

// spec validates one tunnel and converts it. All problems are reported together, each prefixed with the name.
func (t Tunnel) spec(name string) (client.TunnelSpec, error) {
	var errs []error
	bad := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("tunnel %q: "+format, append([]any{name}, a...)...))
	}
	if !auth.ValidName(name) {
		bad("invalid name: use 1-32 chars of a-z, 0-9 and '-', not starting or ending with '-'")
	}
	var kind string
	switch t.Type {
	case TypeHTTP:
		kind = proto.KindHTTP
	case TypeTCP:
		kind = proto.KindTCP
	case TypeSSH:
		kind = proto.KindSSH
		if t.PublicPort {
			kind = proto.KindTCP
		}
	case "":
		bad("type is required (%s, %s or %s)", TypeHTTP, TypeTCP, TypeSSH)
	default:
		bad("unknown type %q (want %s, %s or %s)", t.Type, TypeHTTP, TypeTCP, TypeSSH)
	}
	addr := t.Addr
	if addr == "" && t.Type == TypeSSH {
		addr = DefaultSSHAddr
	}
	switch {
	case addr == "" && t.Type != "" && t.Type != TypeSSH:
		bad("addr is required for %s tunnels", t.Type)
	case addr != "":
		norm, err := ParseTarget(addr)
		if err != nil {
			bad("addr: %v", err)
		} else {
			addr = norm
		}
	}
	if (t.Private || t.PublicPort) && t.Type != TypeSSH && t.Type != "" {
		bad("private and public_port are only valid for ssh tunnels")
	}
	if t.Private && t.PublicPort {
		bad("private and public_port cannot be combined: a public port has no gateway to authenticate")
	}
	if t.Inspect && t.Type != TypeHTTP && t.Type != "" {
		bad("inspect is only valid for http tunnels")
	}
	if t.RemotePort != 0 {
		switch {
		case t.RemotePort < 1 || t.RemotePort > 65535:
			bad("remote_port %d out of range (1-65535)", t.RemotePort)
		case t.Type == TypeHTTP:
			bad("remote_port is only valid for tcp tunnels and ssh tunnels with public_port: true")
		case t.Type == TypeSSH && !t.PublicPort:
			bad("remote_port on an ssh tunnel needs public_port: true (otherwise it is reached through the SSH gateway and has no public port)")
		}
	}
	if len(errs) > 0 {
		return client.TunnelSpec{}, errors.Join(errs...)
	}
	return client.TunnelSpec{Kind: kind, Name: name, LocalAddr: addr, RemotePort: t.RemotePort, Private: t.Private, Inspect: t.Inspect}, nil
}

// normalizeServer mirrors `porthole login`: trailing slashes are dropped and client.ConnectURL must accept the URL
// (http or https, a host, no credentials). A query or fragment is rejected here because ConnectURL would drop it
// silently. An empty value means "not set".
func normalizeServer(s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if s == "" {
		return "", nil
	}
	if strings.ContainsAny(s, "?#") {
		return "", fmt.Errorf("invalid server URL %q: must not contain a query or fragment", s)
	}
	if _, err := client.ConnectURL(s); err != nil {
		return "", err
	}
	return s, nil
}

// Specs converts the file to tunnel specs sorted by name. Without names it returns the enabled tunnels. With names
// it returns exactly those tunnels, enabled or not (like `ngrok start <name>`), and an unknown name is an error.
// Duplicate names are returned once.
func (f *File) Specs(names ...string) ([]client.TunnelSpec, error) {
	var selected []string
	if len(names) == 0 {
		for _, name := range sortedKeys(f.Tunnels) {
			if f.Tunnels[name].IsEnabled() {
				selected = append(selected, name)
			}
		}
	} else {
		selected = slices.Clone(names)
		slices.Sort(selected)
		selected = slices.Compact(selected)
		var errs []error
		for _, name := range selected {
			if _, ok := f.Tunnels[name]; !ok {
				errs = append(errs, fmt.Errorf("tunnel %q is not defined in the tunnels file", name))
			}
		}
		if err := errors.Join(errs...); err != nil {
			return nil, err
		}
	}
	specs := make([]client.TunnelSpec, 0, len(selected))
	var errs []error
	for _, name := range selected {
		spec, err := f.Tunnels[name].spec(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		specs = append(specs, spec)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return specs, nil
}

// Diff is the difference between two tunnel sets, by name. Every slice is sorted and non-nil.
type Diff struct {
	// Added tunnels exist only in the new set.
	Added []string
	// Removed tunnels exist only in the old set.
	Removed []string
	// Changed tunnels exist in both sets with a different kind, local address or remote port.
	Changed []string
	// Unchanged tunnels are identical in both sets.
	Unchanged []string
}

// Empty reports whether the two sets are the same.
func (d Diff) Empty() bool { return len(d.Added)+len(d.Removed)+len(d.Changed) == 0 }

// DiffSpecs compares two tunnel sets by Name. If a name occurs more than once in a set the last entry counts.
func DiffSpecs(oldSpecs, newSpecs []client.TunnelSpec) Diff {
	oldByName := make(map[string]client.TunnelSpec, len(oldSpecs))
	for _, s := range oldSpecs {
		oldByName[s.Name] = s
	}
	newByName := make(map[string]client.TunnelSpec, len(newSpecs))
	for _, s := range newSpecs {
		newByName[s.Name] = s
	}
	d := Diff{Added: []string{}, Removed: []string{}, Changed: []string{}, Unchanged: []string{}}
	for name, n := range newByName {
		o, ok := oldByName[name]
		switch {
		case !ok:
			d.Added = append(d.Added, name)
		case o.Kind != n.Kind || o.LocalAddr != n.LocalAddr || o.RemotePort != n.RemotePort:
			d.Changed = append(d.Changed, name)
		default:
			d.Unchanged = append(d.Unchanged, name)
		}
	}
	for name := range oldByName {
		if _, ok := newByName[name]; !ok {
			d.Removed = append(d.Removed, name)
		}
	}
	slices.Sort(d.Added)
	slices.Sort(d.Removed)
	slices.Sort(d.Changed)
	slices.Sort(d.Unchanged)
	return d
}

// ParseTarget turns a local target into "host:port". A bare port means 127.0.0.1:<port>, and so does ":port".
// The grammar is the one of the `porthole http|tcp|ssh` argument (internal/cli/clientcmd.parseTarget).
func ParseTarget(s string) (string, error) { return client.ParseTarget(s) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// RemoteAllow is the value of the allow_remote key: `none`, `any`, or a list of local targets. "ssh" stands for
// DefaultSSHAddr, the rest follows ParseTarget. An empty list is the same as `none`. `any` permits every target except
// link-local addresses, which must be listed verbatim.
type RemoteAllow struct {
	Targets []string
	Any     bool
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *RemoteAllow) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Value {
		case "none":
			r.Targets, r.Any = nil, false
		case "any":
			r.Targets, r.Any = nil, true
		default:
			return fmt.Errorf("line %d: allow_remote must be a list of targets, none or any, got %q", n.Line, n.Value)
		}
		return nil
	case yaml.SequenceNode:
		targets := make([]string, 0, len(n.Content))
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: allow_remote entries must be \"ssh\", a port or host:port", item.Line)
			}
			if item.Value == "ssh" {
				targets = append(targets, DefaultSSHAddr)
				continue
			}
			norm, err := ParseTarget(item.Value)
			if err != nil {
				return fmt.Errorf("line %d: allow_remote: %w", item.Line, err)
			}
			targets = append(targets, norm)
		}
		r.Targets, r.Any = targets, false
		return nil
	default:
		return fmt.Errorf("line %d: allow_remote must be a list of targets, none or any", n.Line)
	}
}

// RemotePolicy converts the allow_remote key to a client policy: nil (this machine only, see client.RemotePolicy)
// when the key is missing.
func (f *File) RemotePolicy() *client.RemotePolicy {
	if f == nil || f.AllowRemote == nil {
		return nil
	}
	return &client.RemotePolicy{Targets: slices.Clone(f.AllowRemote.Targets), Any: f.AllowRemote.Any}
}
