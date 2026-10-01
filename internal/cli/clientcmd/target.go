// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// parseTarget turns the CLI argument into a local "host:port". A bare port means 127.0.0.1:<port>; ":port" does too.
func parseTarget(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", errors.New("missing local port or address")
	}
	if !strings.ContainsAny(arg, ":") {
		port, err := parsePort(arg)
		if err != nil {
			return "", fmt.Errorf("invalid local target %q: want a port or host:port", arg)
		}
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
	}
	host, portStr, err := net.SplitHostPort(arg)
	if err != nil {
		return "", fmt.Errorf("invalid local target %q: want a port or host:port", arg)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid local target %q: %w", arg, err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if strings.ContainsAny(host, " \t/\\") {
		return "", fmt.Errorf("invalid local target %q: bad host", arg)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %q must be a number from 1 to 65535", s)
	}
	return p, nil
}

// osUser returns the current user name for `ssh user@host`, without a Windows domain prefix.
func osUser() string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	if name == "" {
		name = os.Getenv("USERNAME")
	}
	if name == "" {
		name = os.Getenv("USER")
	}
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return "<user>"
	}
	return name
}
