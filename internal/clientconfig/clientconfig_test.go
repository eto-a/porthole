// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientconfig

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/proto"
)

const goodFile = `version: 1
server: https://tun.example.com/
tunnels:
  blog:
    type: http
    addr: 3000
  db:
    type: tcp
    addr: nas.local:5432
    remote_port: 20017
  ssh:
    type: ssh
  old:
    type: http
    addr: ":8081"
    enabled: false
`

func TestParseGood(t *testing.T) {
	f, err := Parse([]byte(goodFile))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Version != 1 {
		t.Errorf("Version = %d", f.Version)
	}
	if f.Server != "https://tun.example.com" {
		t.Errorf("Server = %q, want trailing slash dropped", f.Server)
	}
	want := map[string]Tunnel{
		"blog": {Type: "http", Addr: "127.0.0.1:3000"},
		"db":   {Type: "tcp", Addr: "nas.local:5432", RemotePort: 20017},
		"ssh":  {Type: "ssh", Addr: "127.0.0.1:22"},
		"old":  {Type: "http", Addr: "127.0.0.1:8081", Enabled: new(false)},
	}
	if !reflect.DeepEqual(f.Tunnels, want) {
		t.Errorf("Tunnels = %+v\nwant %+v", f.Tunnels, want)
	}
}

func TestParseValid(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		tunnels int
		server  string
	}{
		{"no tunnels key", "version: 1\n", 0, ""},
		{"empty tunnels map", "version: 1\ntunnels: {}\n", 0, ""},
		{"null tunnels", "version: 1\ntunnels:\n", 0, ""},
		{"comments around", "# hi\nversion: 1 # v\n# bye\n", 0, ""},
		{"bom", "\ufeffversion: 1\n", 0, ""},
		{"server http with port", "version: 1\nserver: http://127.0.0.1:8080\n", 0, "http://127.0.0.1:8080"},
		{"server with sub-path", "version: 1\nserver: https://example.com/porthole//\n", 0, "https://example.com/porthole"},
		{"empty server is unset", "version: 1\nserver: \"\"\n", 0, ""},
		{"ipv6 addr", "version: 1\ntunnels:\n  a:\n    type: tcp\n    addr: '[::1]:80'\n", 1, ""},
		{"max name", "version: 1\ntunnels:\n  " + strings.Repeat("a", 32) + ":\n    type: http\n    addr: 1\n", 1, ""},
		{"remote port on public-port ssh", "version: 1\ntunnels:\n  s:\n    type: ssh\n    public_port: true\n    remote_port: 2222\n", 1, ""},
		{"private ssh", "version: 1\ntunnels:\n  s:\n    type: ssh\n    private: true\n", 1, ""},
		{"inspect http", "version: 1\ntunnels:\n  w:\n    type: http\n    addr: 3000\n    inspect: true\n", 1, ""},
		{"enabled true", "version: 1\ntunnels:\n  s:\n    type: ssh\n    enabled: true\n", 1, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(f.Tunnels) != tc.tunnels {
				t.Errorf("tunnels = %d, want %d", len(f.Tunnels), tc.tunnels)
			}
			if f.Server != tc.server {
				t.Errorf("server = %q, want %q", f.Server, tc.server)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string // every substring must appear in the error
	}{
		{"empty", "", []string{"file is empty"}},
		{"only whitespace", "  \n\n", []string{"file is empty"}},
		{"only comment", "# nothing\n", []string{"file is empty"}},
		{"no version", "tunnels: {}\n", []string{"missing version"}},
		{"version 0", "version: 0\n", []string{"missing version"}},
		{"version 2", "version: 2\n", []string{"unsupported version 2"}},
		{"version string", "version: one\n", []string{"parse:"}},
		{"unknown top key", "version: 1\nfoo: bar\n", []string{"field foo not found"}},
		{"unknown tunnel key", "version: 1\ntunnels:\n  a:\n    type: http\n    addr: 1\n    port: 2\n", []string{"field port not found"}},
		{"two documents", "version: 1\n---\nversion: 1\n", []string{"more than one YAML document"}},
		{"not a mapping", "- a\n- b\n", []string{"parse:"}},
		{"tunnels is a list", "version: 1\ntunnels:\n  - a\n", []string{"parse:"}},
		{"duplicate tunnel", "version: 1\ntunnels:\n  a:\n    type: ssh\n  a:\n    type: ssh\n", []string{"parse:"}},
		{"enabled not a bool", "version: 1\ntunnels:\n  a:\n    type: ssh\n    enabled: maybe\n", []string{"parse:"}},
		{"broken yaml", "version: 1\ntunnels: [\n", []string{"parse:"}},

		{"top-level token", "version: 1\ntoken: ph_x_y\n", []string{"token is not allowed in the tunnels file", "config.yaml or token_file"}},
		{"tunnel token", "version: 1\ntunnels:\n  a:\n    type: ssh\n    token: x\n", []string{`tunnel "a"`, "token is not allowed"}},
		{"empty token still rejected", "version: 1\ntoken:\n", []string{"token is not allowed"}},

		{"bad name upper", tunnelFile("Blog", "type: http\naddr: 1"), []string{`tunnel "Blog": invalid name`}},
		{"bad name dash", tunnelFile("-a", "type: http\naddr: 1"), []string{`tunnel "-a": invalid name`}},
		{"bad name underscore", tunnelFile("my_app", "type: http\naddr: 1"), []string{`tunnel "my_app": invalid name`}},
		{"name too long", tunnelFile(strings.Repeat("a", 33), "type: http\naddr: 1"), []string{"invalid name"}},
		{"no type", tunnelFile("a", "addr: 1"), []string{`tunnel "a": type is required`}},
		{"null tunnel", "version: 1\ntunnels:\n  a:\n", []string{`tunnel "a": type is required`}},
		{"unknown type", tunnelFile("a", "type: udp\naddr: 1"), []string{`tunnel "a": unknown type "udp"`}},
		{"http without addr", tunnelFile("a", "type: http"), []string{`tunnel "a": addr is required for http`}},
		{"tcp without addr", tunnelFile("a", "type: tcp"), []string{`tunnel "a": addr is required for tcp`}},
		{"bad addr host", tunnelFile("a", "type: tcp\naddr: 'a b:80'"), []string{`tunnel "a": addr:`, "bad host"}},
		{"addr port 0", tunnelFile("a", "type: tcp\naddr: 0"), []string{`tunnel "a": addr:`}},
		{"addr port high", tunnelFile("a", "type: tcp\naddr: host:70000"), []string{`tunnel "a": addr:`, "1 to 65535"}},
		{"addr no port", tunnelFile("a", "type: tcp\naddr: 'host:'"), []string{`tunnel "a": addr:`}},
		{"addr garbage", tunnelFile("a", "type: tcp\naddr: nope"), []string{`tunnel "a": addr:`}},
		{"remote port too big", tunnelFile("db", "type: tcp\naddr: 1\nremote_port: 99999"), []string{`tunnel "db": remote_port 99999 out of range`}},
		{"remote port negative", tunnelFile("db", "type: tcp\naddr: 1\nremote_port: -1"), []string{`tunnel "db": remote_port -1 out of range`}},
		{"remote port on http", tunnelFile("a", "type: http\naddr: 1\nremote_port: 80"), []string{`tunnel "a": remote_port is only valid for tcp tunnels and ssh tunnels with public_port`}},
		{"remote port on gateway ssh", tunnelFile("a", "type: ssh\nremote_port: 2222"), []string{`tunnel "a": remote_port on an ssh tunnel needs public_port: true`}},
		{"inspect on tcp", tunnelFile("a", "type: tcp\naddr: 1\ninspect: true"), []string{`inspect is only valid for http`}},
		{"private on tcp", tunnelFile("a", "type: tcp\naddr: 1\nprivate: true"), []string{`tunnel "a": private and public_port are only valid for ssh`}},
		{"public_port on http", tunnelFile("a", "type: http\naddr: 1\npublic_port: true"), []string{`private and public_port are only valid for ssh`}},
		{"private and public_port", tunnelFile("a", "type: ssh\nprivate: true\npublic_port: true"), []string{`cannot be combined`}},

		{"server ftp", "version: 1\nserver: ftp://x.example.com\n", []string{"server:", "scheme must be http or https"}},
		{"server no scheme", "version: 1\nserver: tun.example.com\n", []string{"server:"}},
		{"server no host", "version: 1\nserver: https://\n", []string{"server:", "missing host"}},
		{"server credentials", "version: 1\nserver: https://u:p@x.example.com\n", []string{"server:", "credentials"}},
		{"server query", "version: 1\nserver: https://x.example.com/?a=1\n", []string{"server:", "query or fragment"}},
		{"server fragment", "version: 1\nserver: https://x.example.com/#a\n", []string{"server:", "query or fragment"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse([]byte(tc.in))
			if err == nil {
				t.Fatalf("Parse succeeded: %+v", f)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func tunnelFile(name, body string) string {
	var b strings.Builder
	b.WriteString("version: 1\ntunnels:\n  " + name + ":\n")
	for _, l := range strings.Split(body, "\n") {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}

func TestParseCollectsAllErrors(t *testing.T) {
	in := `version: 1
server: ftp://x.example.com
tunnels:
  Bad_Name:
    type: http
    addr: 1
  db:
    type: tcp
    addr: 1
    remote_port: 99999
  web:
    type: http
  zzz:
    type: nope
`
	_, err := Parse([]byte(in))
	if err == nil {
		t.Fatal("Parse succeeded")
	}
	for _, w := range []string{"server:", `tunnel "Bad_Name"`, `tunnel "db": remote_port 99999 out of range`, `tunnel "web": addr is required`, `tunnel "zzz": unknown type`} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error does not contain %q:\n%v", w, err)
		}
	}
	// Errors are reported in tunnel-name order.
	msg := err.Error()
	if strings.Index(msg, `"Bad_Name"`) > strings.Index(msg, `"db"`) || strings.Index(msg, `"db"`) > strings.Index(msg, `"web"`) {
		t.Errorf("errors are not sorted by tunnel name:\n%v", err)
	}
}

func TestParseOneTunnelAllProblems(t *testing.T) {
	_, err := Parse([]byte(tunnelFile("A", "type: http\nremote_port: 99999")))
	if err == nil {
		t.Fatal("Parse succeeded")
	}
	for _, w := range []string{"invalid name", "addr is required", "remote_port 99999 out of range"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error does not contain %q:\n%v", w, err)
		}
	}
}

func TestParseSizeCap(t *testing.T) {
	pad := strings.Repeat("# x\n", MaxFileSize/4)
	ok := "version: 1\n" + pad[:MaxFileSize-len("version: 1\n")]
	if len(ok) != MaxFileSize {
		t.Fatalf("test setup: len = %d", len(ok))
	}
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatalf("a file of exactly MaxFileSize bytes: %v", err)
	}
	if _, err := Parse([]byte(ok + "#")); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("MaxFileSize+1 bytes: err = %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("good", func(t *testing.T) {
		f, err := Load(write("good.yaml", goodFile))
		if err != nil {
			t.Fatal(err)
		}
		if len(f.Tunnels) != 4 {
			t.Errorf("tunnels = %d", len(f.Tunnels))
		}
	})
	t.Run("missing", func(t *testing.T) {
		_, err := Load(filepath.Join(dir, "nope.yaml"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("err = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("invalid mentions the path", func(t *testing.T) {
		p := write("bad.yaml", "version: 7\n")
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "unsupported version 7") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("size cap", func(t *testing.T) {
		big := "version: 1\n" + strings.Repeat("#", MaxFileSize)
		_, err := Load(write("big.yaml", big))
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := Load(dir); err == nil {
			t.Fatal("Load of a directory succeeded")
		}
	})
}

func mustParse(t *testing.T, in string) *File {
	t.Helper()
	f, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

func TestSpecsEnabled(t *testing.T) {
	f := mustParse(t, goodFile)
	got, err := f.Specs()
	if err != nil {
		t.Fatal(err)
	}
	want := []client.TunnelSpec{
		{Kind: proto.KindHTTP, Name: "blog", LocalAddr: "127.0.0.1:3000"},
		{Kind: proto.KindTCP, Name: "db", LocalAddr: "nas.local:5432", RemotePort: 20017},
		{Kind: proto.KindSSH, Name: "ssh", LocalAddr: "127.0.0.1:22"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Specs() = %+v\nwant %+v", got, want)
	}
}

func TestSpecsNames(t *testing.T) {
	f := mustParse(t, goodFile)

	// Named tunnels are returned sorted and once, and a disabled tunnel is included when asked for explicitly.
	got, err := f.Specs("ssh", "old", "blog", "ssh")
	if err != nil {
		t.Fatal(err)
	}
	want := []client.TunnelSpec{
		{Kind: proto.KindHTTP, Name: "blog", LocalAddr: "127.0.0.1:3000"},
		{Kind: proto.KindHTTP, Name: "old", LocalAddr: "127.0.0.1:8081"},
		{Kind: proto.KindSSH, Name: "ssh", LocalAddr: "127.0.0.1:22"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Specs(names) = %+v\nwant %+v", got, want)
	}

	// Unknown names are all reported.
	_, err = f.Specs("blog", "nope", "zzz")
	if err == nil {
		t.Fatal("unknown names accepted")
	}
	for _, w := range []string{`"nope"`, `"zzz"`} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not contain %s", err, w)
		}
	}
	if strings.Contains(err.Error(), `"blog"`) {
		t.Errorf("error mentions a known tunnel: %v", err)
	}
}

func TestSpecsEmpty(t *testing.T) {
	for _, in := range []string{"version: 1\n", "version: 1\ntunnels:\n  a:\n    type: ssh\n    enabled: false\n"} {
		got, err := mustParse(t, in).Specs()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("Specs() = %+v, want none", got)
		}
	}
}

func TestSSHSpecModes(t *testing.T) {
	f, err := Parse([]byte("version: 1\ntunnels:\n  a:\n    type: ssh\n  b:\n    type: ssh\n    private: true\n" +
		"  c:\n    type: ssh\n    public_port: true\n    remote_port: 20022\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.Specs()
	if err != nil {
		t.Fatal(err)
	}
	want := []client.TunnelSpec{
		{Kind: proto.KindSSH, Name: "a", LocalAddr: DefaultSSHAddr},
		{Kind: proto.KindSSH, Name: "b", LocalAddr: DefaultSSHAddr, Private: true},
		{Kind: proto.KindTCP, Name: "c", LocalAddr: DefaultSSHAddr, RemotePort: 20022},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Specs() = %+v\nwant %+v", got, want)
	}
}

func TestSpecsRevalidatesHandBuiltFile(t *testing.T) {
	f := &File{Version: 1, Tunnels: map[string]Tunnel{
		"ok":  {Type: "ssh"},
		"bad": {Type: "tcp"},
	}}
	if _, err := f.Specs(); err == nil || !strings.Contains(err.Error(), `tunnel "bad"`) {
		t.Fatalf("err = %v", err)
	}
	got, err := f.Specs("ok")
	if err != nil || len(got) != 1 || got[0].LocalAddr != DefaultSSHAddr || got[0].Kind != proto.KindSSH {
		t.Fatalf("Specs(ok) = %+v, %v", got, err)
	}
}

func TestDiffSpecs(t *testing.T) {
	a := client.TunnelSpec{Kind: proto.KindHTTP, Name: "a", LocalAddr: "127.0.0.1:1"}
	b := client.TunnelSpec{Kind: proto.KindTCP, Name: "b", LocalAddr: "127.0.0.1:2", RemotePort: 20000}
	c := client.TunnelSpec{Kind: proto.KindTCP, Name: "c", LocalAddr: "127.0.0.1:3"}
	d := client.TunnelSpec{Kind: proto.KindHTTP, Name: "d", LocalAddr: "127.0.0.1:4"}
	e := client.TunnelSpec{Kind: proto.KindHTTP, Name: "e", LocalAddr: "127.0.0.1:5"}

	with := func(s client.TunnelSpec, mut func(*client.TunnelSpec)) client.TunnelSpec { mut(&s); return s }

	tests := []struct {
		name     string
		old, new []client.TunnelSpec
		want     Diff
	}{
		{"both empty", nil, nil, Diff{[]string{}, []string{}, []string{}, []string{}}},
		{"all added", nil, []client.TunnelSpec{b, a}, Diff{Added: []string{"a", "b"}, Removed: []string{}, Changed: []string{}, Unchanged: []string{}}},
		{"all removed", []client.TunnelSpec{b, a}, nil, Diff{Added: []string{}, Removed: []string{"a", "b"}, Changed: []string{}, Unchanged: []string{}}},
		{"same in another order", []client.TunnelSpec{a, b}, []client.TunnelSpec{b, a}, Diff{Added: []string{}, Removed: []string{}, Changed: []string{}, Unchanged: []string{"a", "b"}}},
		{
			"mixed",
			[]client.TunnelSpec{e, d, c, b, a},
			[]client.TunnelSpec{
				a,
				with(b, func(s *client.TunnelSpec) { s.RemotePort = 20001 }),
				with(c, func(s *client.TunnelSpec) { s.LocalAddr = "127.0.0.1:99" }),
				with(d, func(s *client.TunnelSpec) { s.Kind = proto.KindTCP }),
				{Kind: proto.KindHTTP, Name: "f", LocalAddr: "127.0.0.1:6"},
			},
			Diff{Added: []string{"f"}, Removed: []string{"e"}, Changed: []string{"b", "c", "d"}, Unchanged: []string{"a"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DiffSpecs(tc.old, tc.new)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DiffSpecs = %+v\nwant %+v", got, tc.want)
			}
			if wantEmpty := len(tc.want.Added)+len(tc.want.Removed)+len(tc.want.Changed) == 0; got.Empty() != wantEmpty {
				t.Errorf("Empty() = %v, want %v", got.Empty(), wantEmpty)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	good := []struct{ in, want string }{
		{"3000", "127.0.0.1:3000"},
		{" 3000 ", "127.0.0.1:3000"},
		{":3000", "127.0.0.1:3000"},
		{"1", "127.0.0.1:1"},
		{"65535", "127.0.0.1:65535"},
		{"localhost:8080", "localhost:8080"},
		{"nas.local:5432", "nas.local:5432"},
		{"192.168.1.10:22", "192.168.1.10:22"},
		{"[::1]:80", "[::1]:80"},
		{"[fe80::1%eth0]:80", "[fe80::1%eth0]:80"},
	}
	for _, tc := range good {
		got, err := ParseTarget(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParseTarget(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	bad := []string{"", "  ", "0", "65536", "-1", "abc", "1.5", "host", "host:", "host:0", "host:99999", "host:abc", "a b:80", "a/b:80", `a\b:80`, "::1", "a:b:c", "http://x:80"}
	for _, in := range bad {
		if got, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) = %q, want an error", in, got)
		}
	}
}

func TestTunnelIsEnabled(t *testing.T) {
	if !(Tunnel{}).IsEnabled() {
		t.Error("nil Enabled must mean enabled")
	}
	if !(Tunnel{Enabled: new(true)}).IsEnabled() {
		t.Error("Enabled=true")
	}
	if (Tunnel{Enabled: new(false)}).IsEnabled() {
		t.Error("Enabled=false")
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"", "version: 1\n", goodFile, "version: 2\n", "token: x\n", "---\n---\n", "version: 1\ntunnels: [\n",
		"version: 1\ntunnels:\n  a: &x\n    type: http\n    addr: 1\n  b: *x\n",
		"version: 1\ntunnels:\n  a:\n    type: tcp\n    addr: '[::1]:99999'\n    remote_port: -5\n",
		"\ufeffversion: 1\nserver: http://[::1]:80/a?b#c\n",
		"version: 1\ntunnels:\n  a:\n    token: x\n",
		tunnelFile("a", "type: ssh\nenabled: false"),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil {
			return
		}
		// A file that parses must convert to specs the client accepts, and parsing the normalized values again
		// must not change them.
		specs, err := file.Specs()
		if err != nil {
			t.Fatalf("Parse accepted a file whose Specs fail: %v", err)
		}
		for _, s := range specs {
			again, err := ParseTarget(s.LocalAddr)
			if err != nil || again != s.LocalAddr {
				t.Fatalf("LocalAddr %q is not stable: %q, %v", s.LocalAddr, again, err)
			}
		}
		if _, err := file.Specs(sortedKeys(file.Tunnels)...); err != nil {
			t.Fatalf("Specs(all names): %v", err)
		}
	})
}

func FuzzParseTarget(f *testing.F) {
	for _, s := range []string{"3000", ":3000", "host:80", "[::1]:80", "", "a b:1", "::", "[", "1:2:3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseTarget(s)
		if err != nil {
			return
		}
		again, err := ParseTarget(got)
		if err != nil || again != got {
			t.Fatalf("ParseTarget(%q) = %q, but parsing that again gives %q, %v", s, got, again, err)
		}
	})
}
