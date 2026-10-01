// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package traffic

import (
	"net/url"
	"slices"
	"strings"
)

// Redacted replaces the value of a sensitive query parameter.
const Redacted = "REDACTED"

// Field length limits keep one entry small whatever a visitor sends.
const (
	maxPath      = 2048
	maxQuery     = 2048
	maxUserAgent = 512
	maxReferer   = 1024
	maxHost      = 255
	maxName      = 255
)

// sensitiveParts are matched case-insensitively as substrings of a query parameter name, so api_key, apikey,
// access_token, refresh_token, client_secret and X-Auth are covered together with token, key, password, secret, auth,
// signature, session and credential.
var sensitiveParts = []string{"token", "key", "password", "passwd", "secret", "auth", "signature", "session", "credential"}

// sensitiveNames are short names that would match too much as substrings ("code" is in "encode" and "zipcode"), so
// they are masked only as the whole name: OAuth codes, presigned-URL signatures, session ids, JWTs, one-time codes.
var sensitiveNames = []string{"code", "sig", "sid", "jwt", "otp", "ticket"}

// sensitivePrefixes: AWS presigned URLs carry X-Amz-Signature, X-Amz-Credential, X-Amz-Security-Token and more.
var sensitivePrefixes = []string{"x-amz-"}

func sensitiveParam(name string) bool {
	if dec, err := url.QueryUnescape(name); err == nil {
		name = dec
	}
	name = strings.ToLower(name)
	if slices.Contains(sensitiveNames, name) {
		return true
	}
	for _, p := range sensitivePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, p := range sensitiveParts {
		if strings.Contains(name, p) {
			return true
		}
	}
	return false
}

// MaskQuery replaces the values of sensitive parameters (token, key, password, secret, auth and names containing
// them) in a raw query string with Redacted. Order and the other parameters are preserved byte for byte.
func MaskQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		name, _, hasValue := strings.Cut(p, "=")
		if sensitiveParam(name) {
			if hasValue {
				parts[i] = name + "=" + Redacted
			} else {
				parts[i] = name
			}
		}
	}
	return strings.Join(parts, "&")
}

// maskURL masks the query of an absolute or relative URL string (the Referer header) and drops the fragment.
func maskURL(raw string) string {
	raw, _, _ = strings.Cut(raw, "#")
	base, q, ok := strings.Cut(raw, "?")
	if !ok {
		return raw
	}
	return base + "?" + MaskQuery(q)
}

// clip shortens s to at most n bytes without cutting a UTF-8 sequence in half.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
