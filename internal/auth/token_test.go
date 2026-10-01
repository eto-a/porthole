// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"testing"
)

func TestGenerateParseVerify(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := tok.String()
	if !strings.HasPrefix(s, "ph_") || len(s) != 3+12+1+52 {
		t.Fatalf("unexpected token form %q (len %d)", s, len(s))
	}
	got, err := Parse(s)
	if err != nil {
		t.Fatalf("parse own token: %v", err)
	}
	if got != tok {
		t.Fatalf("parse: got %+v want %+v", got, tok)
	}
	if !Verify(got.Secret, tok.Hash()) {
		t.Fatal("verify failed for correct secret")
	}
	other, _ := Generate()
	if Verify(other.Secret, tok.Hash()) {
		t.Fatal("verify succeeded for wrong secret")
	}
	if len(tok.Last4()) != 4 || !strings.HasSuffix(tok.Secret, tok.Last4()) {
		t.Fatalf("last4 = %q", tok.Last4())
	}
}

func TestGenerateUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		tok, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.ID] {
			t.Fatalf("duplicate id %s", tok.ID)
		}
		seen[tok.ID] = true
	}
}

func TestParseRejects(t *testing.T) {
	valid, _ := Generate()
	bad := []string{
		"",
		"ph_",
		valid.ID + "_" + valid.Secret,         // no prefix
		"tk_" + valid.ID + "_" + valid.Secret, // wrong prefix
		"ph_" + valid.ID + valid.Secret,       // no separator
		"ph_" + valid.ID[:11] + "_" + valid.Secret, // short id
		"ph_" + valid.ID + "_" + valid.Secret[:51], // short secret
		"ph_" + strings.ToUpper(valid.ID) + "_" + valid.Secret,
		"ph_" + valid.ID + "_" + valid.Secret + "_x",
		"ph_" + valid.ID + "_" + valid.Secret[:51] + "1", // '1' is not base32
	}
	for _, s := range bad {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, s := range []string{"a", "home", "office-nas", "http-8080", strings.Repeat("a", 32)} {
		if !ValidName(s) {
			t.Errorf("ValidName(%q) = false", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", "Home", "a_b", "a.b", strings.Repeat("a", 33), "ä"} {
		if ValidName(s) {
			t.Errorf("ValidName(%q) = true", s)
		}
	}
}

func FuzzParse(f *testing.F) {
	tok, _ := Generate()
	f.Add(tok.String())
	f.Add("ph_aaaaaaaaaaaa_")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		if err == nil && p.String() != s {
			t.Fatalf("Parse(%q) round-trips to %q", s, p.String())
		}
	})
}

func TestValidScopeConnect(t *testing.T) {
	for s, want := range map[string]bool{"connect:home": true, "connect:": false, "connect:Bad_Name": false, "connect": false} {
		if got := ValidScope(s); got != want {
			t.Errorf("ValidScope(%q) = %v, want %v", s, got, want)
		}
	}
}
