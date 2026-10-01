// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package auth implements porthole client tokens: `ph_<id>_<secret>`.
//
// The id is public and used for lookup and display. Only sha256(secret) is stored on the server; the secret
// carries 256 bits of entropy, so a fast hash is sufficient (see DESIGN.md §3.3).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"regexp"
	"strings"
)

// Prefix starts every token so secret scanners can recognise leaked tokens.
const Prefix = "ph_"

const (
	idLen     = 12 // base32 characters
	secretLen = 32 // random bytes
)

// b32 is lowercase RFC 4648 base32 without padding.
var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	idRe     = regexp.MustCompile(`^[a-z2-7]{12}$`)
	secretRe = regexp.MustCompile(`^[a-z2-7]{52}$`)
)

// ErrMalformed is returned for strings that are not porthole tokens.
var ErrMalformed = errors.New("auth: malformed token")

// Token is a parsed client token.
type Token struct {
	ID     string
	Secret string
}

// String returns the wire form ph_<id>_<secret>.
func (t Token) String() string { return Prefix + t.ID + "_" + t.Secret }

// Hash returns sha256 of the secret, the only form stored by the server.
func (t Token) Hash() []byte { return HashSecret(t.Secret) }

// Last4 returns the last four characters of the secret, safe to display.
func (t Token) Last4() string { return t.Secret[len(t.Secret)-4:] }

// Generate creates a new random token.
func Generate() (Token, error) {
	idBytes := make([]byte, 8) // 8 bytes → 13 base32 chars, truncated to 12 (60 bits)
	if _, err := rand.Read(idBytes); err != nil {
		return Token{}, err
	}
	secret := make([]byte, secretLen)
	if _, err := rand.Read(secret); err != nil {
		return Token{}, err
	}
	return Token{ID: b32.EncodeToString(idBytes)[:idLen], Secret: b32.EncodeToString(secret)}, nil
}

// Parse validates the format of s and splits it. It does not check the token against any store.
func Parse(s string) (Token, error) {
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return Token{}, ErrMalformed
	}
	id, secret, ok := strings.Cut(rest, "_")
	if !ok || !idRe.MatchString(id) || !secretRe.MatchString(secret) {
		return Token{}, ErrMalformed
	}
	return Token{ID: id, Secret: secret}, nil
}

// HashSecret returns sha256(secret).
func HashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// Verify reports whether secret matches the stored hash, in constant time.
func Verify(secret string, storedHash []byte) bool {
	return subtle.ConstantTimeCompare(HashSecret(secret), storedHash) == 1
}

// Scopes granted to tokens.
const (
	ScopeTunnelHTTP = "tunnel:http"
	ScopeTunnelTCP  = "tunnel:tcp"
	ScopeTunnelUDP  = "tunnel:udp"
)

// DefaultScopes are granted when a token is created without explicit scopes.
var DefaultScopes = []string{ScopeTunnelHTTP, ScopeTunnelTCP, ScopeTunnelUDP}

// ValidScope reports whether s is a known scope.
func ValidScope(s string) bool {
	switch s {
	case ScopeTunnelHTTP, ScopeTunnelTCP, ScopeTunnelUDP:
		return true
	}
	return false
}

// nameRe restricts client and tunnel names to a single DNS-label-safe form.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidName reports whether s is a valid client or tunnel name: 1–32 chars of [a-z0-9-],
// not starting or ending with '-'.
func ValidName(s string) bool { return nameRe.MatchString(s) }
