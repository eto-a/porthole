// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package traffic

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
)

// MaxBodyBytes is how much of a request or response body an inspected request keeps.
const MaxBodyBytes = 64 << 10

// Body is a captured request or response body: at most MaxBodyBytes of it, the full size and whether it was cut.
type Body struct {
	Data      []byte // the first Size bytes (all of them unless Truncated)
	Size      int64  // the real size of the body
	Truncated bool   // Data is shorter than the body
}

type bodyJSON struct {
	Text      *string `json:"text,omitempty"`   // Data when it is valid UTF-8
	Base64    string  `json:"base64,omitempty"` // Data otherwise
	Size      int64   `json:"size"`
	Truncated bool    `json:"truncated,omitempty"`
}

// MarshalJSON writes the data as text when it is valid UTF-8 and as base64 otherwise. A body cut in the middle
// of a multi-byte character is written as base64.
func (b Body) MarshalJSON() ([]byte, error) {
	out := bodyJSON{Size: b.Size, Truncated: b.Truncated}
	switch {
	case len(b.Data) == 0:
	case utf8.Valid(b.Data):
		s := string(b.Data)
		out.Text = &s
	default:
		out.Base64 = base64.StdEncoding.EncodeToString(b.Data)
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads what MarshalJSON wrote.
func (b *Body) UnmarshalJSON(p []byte) error {
	var in bodyJSON
	if err := json.Unmarshal(p, &in); err != nil {
		return err
	}
	*b = Body{Size: in.Size, Truncated: in.Truncated}
	switch {
	case in.Text != nil:
		b.Data = []byte(*in.Text)
	case in.Base64 != "":
		d, err := base64.StdEncoding.DecodeString(in.Base64)
		if err != nil {
			return fmt.Errorf("traffic: body base64: %w", err)
		}
		b.Data = d
	}
	return nil
}

// Detail is what an inspected request keeps besides the metadata of Request (ADR 0005). Cookie, Set-Cookie and every
// header whose name suggests a credential (see isRedactedHeader) are always stored as Redacted.
type Detail struct {
	RequestHeaders  http.Header `json:"request_headers"`
	RequestBody     Body        `json:"request_body"`
	ResponseHeaders http.Header `json:"response_headers"`
	ResponseBody    Body        `json:"response_body"`

	// Target is the request-target as the visitor sent it (path and unmasked query). Replay needs it; it is
	// never serialised.
	Target string `json:"-"`

	size int64 // memory charged against the detail budget, set by Requests.Add
}

// redactedHeaders are stored as Redacted whatever their value.
var redactedHeaders = []string{"Cookie", "Set-Cookie"}

// redactedHeaderParts: a header whose name contains one of these (case-insensitive) is stored as Redacted. That covers
// Authorization, Proxy-Authorization, X-Api-Key, X-Auth-Token, X-Access-Token, X-Amz-Security-Token, X-Csrf-Token,
// X-Goog-Api-Key, X-Hub-Signature-256, webhook secrets and custom headers alike. Credentials in header names we cannot
// guess, or in bodies and paths, are not found: inspected bodies are stored as they are.
var redactedHeaderParts = []string{"token", "secret", "api-key", "apikey", "auth", "session", "signature"}

// notRedactedHeaders are challenges and the like whose names match a part but which carry no credential.
var notRedactedHeaders = []string{"WWW-Authenticate", "Proxy-Authenticate"}

// RedactHeaders returns a copy of h in which the values of credential headers (see Detail) are replaced by
// Redacted. A nil h gives nil.
func RedactHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, v := range h {
		if isRedactedHeader(k) {
			out[k] = []string{Redacted}
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

func isRedactedHeader(name string) bool {
	for _, r := range redactedHeaders {
		if strings.EqualFold(name, r) {
			return true
		}
	}
	for _, r := range notRedactedHeaders {
		if strings.EqualFold(name, r) {
			return false
		}
	}
	lower := strings.ToLower(name)
	for _, p := range redactedHeaderParts {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// IsRedactedHeader reports whether the stored value of the header is masked (Replay must not send it).
func IsRedactedHeader(name string) bool { return isRedactedHeader(name) }

// footprint estimates the memory the detail holds.
func (d *Detail) footprint() int64 {
	n := int64(len(d.RequestBody.Data)+len(d.ResponseBody.Data)+len(d.Target)) + 256
	for _, h := range [...]http.Header{d.RequestHeaders, d.ResponseHeaders} {
		for k, v := range h {
			n += int64(len(k)) + 48
			for _, s := range v {
				n += int64(len(s)) + 16
			}
		}
	}
	return n
}

// prepared returns a copy of d that is safe to store: headers redacted, bodies cut to MaxBodyBytes, size set.
func (d *Detail) prepared() *Detail {
	c := *d
	c.RequestHeaders = RedactHeaders(d.RequestHeaders)
	c.ResponseHeaders = RedactHeaders(d.ResponseHeaders)
	c.RequestBody = c.RequestBody.clipped()
	c.ResponseBody = c.ResponseBody.clipped()
	c.size = c.footprint()
	return &c
}

func (b Body) clipped() Body {
	if len(b.Data) > MaxBodyBytes {
		b.Data = b.Data[:MaxBodyBytes]
		b.Truncated = true
	}
	b.Size = max(b.Size, int64(len(b.Data)))
	return b
}
