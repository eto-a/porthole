// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package traffic

import (
	"net/http"
	"strings"
	"testing"
)

// A10: OAuth codes, presigned-URL signatures and session identifiers in the query are masked.
func TestMaskQueryCommonSecrets(t *testing.T) {
	for _, name := range []string{
		"code", "Code", "sig", "signature", "X-Amz-Signature", "X-Amz-Credential", "x-amz-security-token", "session", "sessionid", "sid",
		"jwt", "access_token", "refresh_token", "client_secret", "apikey", "api_key", "key", "token", "password", "secret", "auth",
	} {
		got := MaskQuery("a=1&" + name + "=VALUE&b=2")
		if strings.Contains(got, "VALUE") || got != "a=1&"+name+"="+Redacted+"&b=2" {
			t.Errorf("%s: %q", name, got)
		}
	}
	// Names that merely contain a short word stay readable.
	for _, name := range []string{"encode", "zipcode", "design", "inside", "q", "page", "state"} {
		if got := MaskQuery(name + "=v"); got != name+"=v" {
			t.Errorf("%s was masked: %q", name, got)
		}
	}
	if got := MaskQuery("code=abc"); got != "code="+Redacted {
		t.Errorf("got %q", got)
	}
	if got := maskURL("https://app.example/cb?code=SECRET&state=ok#frag"); strings.Contains(got, "SECRET") {
		t.Errorf("referer: %q", got)
	}
}

// N-06: headers that carry credentials are stored as Redacted, whatever their exact name.
func TestRedactHeadersByName(t *testing.T) {
	h := http.Header{}
	secret := []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token", "X-Access-Token",
		"X-Amz-Security-Token", "X-Csrf-Token", "X-Goog-Api-Key", "Api-Key", "Apikey", "X-Hub-Signature-256", "X-Session-Id",
		"X-Webhook-Secret", "Authentication", "X-My-Token", "x-custom-auth",
	}
	for _, k := range secret {
		h.Set(k, "VALUE")
	}
	keep := []string{"Content-Type", "User-Agent", "X-Request-Id", "Accept", "Host", "X-Forwarded-For", "Sec-Websocket-Key"}
	for _, k := range keep {
		h.Set(k, "plain")
	}
	out := RedactHeaders(h)
	for _, k := range secret {
		if got := out.Get(k); got != Redacted {
			t.Errorf("%s = %q, want %s", k, got, Redacted)
		}
		if !IsRedactedHeader(k) {
			t.Errorf("IsRedactedHeader(%s) = false: replay would send it", k)
		}
	}
	for _, k := range keep {
		if got := out.Get(k); got != "plain" {
			t.Errorf("%s = %q, want it kept", k, got)
		}
	}
}
