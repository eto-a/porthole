// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package localapi

import "go.uber.org/goleak"

func leakOptions() []goleak.Option { return nil }
