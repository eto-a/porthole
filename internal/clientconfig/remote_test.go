// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientconfig

import (
	"slices"
	"strings"
	"testing"
)

func TestAllowRemote(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		all     bool // nil policy: everything is allowed
		targets []string
		wantErr string
	}{
		{name: "missing key allows all", yaml: "version: 1\n", all: true},
		{name: "none", yaml: "version: 1\nallow_remote: none\n"},
		{name: "empty list is none", yaml: "version: 1\nallow_remote: []\n"},
		{
			name:    "list",
			yaml:    "version: 1\nallow_remote: [ssh, 3000, \":8080\", \"192.168.1.5:80\"]\n",
			targets: []string{"127.0.0.1:22", "127.0.0.1:3000", "127.0.0.1:8080", "192.168.1.5:80"},
		},
		{name: "unknown word", yaml: "version: 1\nallow_remote: all\n", wantErr: "list of targets or none"},
		{name: "bad port", yaml: "version: 1\nallow_remote: [99999]\n", wantErr: "allow_remote"},
		{name: "nested", yaml: "version: 1\nallow_remote: [[3000]]\n", wantErr: "allow_remote entries"},
		{name: "mapping", yaml: "version: 1\nallow_remote: {a: b}\n", wantErr: "allow_remote"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse([]byte(tc.yaml))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p := f.RemotePolicy()
			if tc.all {
				if p != nil {
					t.Fatalf("policy %+v, want nil", p)
				}
				return
			}
			if p == nil || !slices.Equal(p.Targets, tc.targets) && len(tc.targets)+len(p.Targets) > 0 {
				t.Fatalf("targets %+v, want %v", p, tc.targets)
			}
		})
	}
}
