// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package config

import "strconv"

// PublicURL is the address clients should be told to connect to: server_url when set, else built from the public
// scheme, domain and port. It is "https://<domain>" with a placeholder while domain is empty.
func (c *Config) PublicURL() string {
	if u := c.ClientURL(); u != "" {
		return u
	}
	scheme := c.PublicScheme
	if scheme == "" {
		scheme = "https"
	}
	host := c.Domain
	if host == "" {
		host = "<domain>"
	}
	u := scheme + "://" + host
	if c.PublicPort != 0 {
		u += ":" + strconv.Itoa(c.PublicPort)
	}
	return u
}
