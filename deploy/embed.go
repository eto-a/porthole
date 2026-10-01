// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package deploy embeds the service definitions that ship in this directory, so that the packages and
// `porthole service install` use the same text and cannot drift.
package deploy

import _ "embed"

// SystemUnit is the systemd unit of the client daemon for a system-wide install (porthole.service).
//
//go:embed porthole.service
var SystemUnit string

// UserUnit is the systemd user unit of the client daemon (porthole.user.service).
//
//go:embed porthole.user.service
var UserUnit string
