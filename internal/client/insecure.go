// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/url"
	"strings"
)

// PlaintextServer reports whether serverURL sends the token in clear text over a network: an http:// URL whose host
// is not this machine (loopback address or localhost). An unparsable URL is not reported; ConnectURL rejects it.
func PlaintextServer(serverURL string) bool {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Scheme != "http" {
		return false
	}
	return !isLoopbackHost(u.Hostname())
}

// PlaintextWarning is the text of the warning for a server URL that PlaintextServer reports.
func PlaintextWarning(serverURL string) string {
	return "warning: " + serverURL + " is a plain http:// URL: the token and all tunnel traffic metadata are sent unencrypted; use https://"
}
