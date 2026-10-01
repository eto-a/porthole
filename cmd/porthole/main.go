// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Command porthole exposes local services through a porthole server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/eto-a/porthole/internal/cli/clientcmd"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := clientcmd.NewRoot(version).ExecuteContext(ctx)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "porthole:", err)
		os.Exit(clientcmd.ExitCode(err))
	}
}
