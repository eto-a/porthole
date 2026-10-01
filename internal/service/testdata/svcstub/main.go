// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Command svcstub is a tiny Windows service for TestWindowsServiceLifecycle: it reports Running at once, appends a
// line to the marker file for every ParamChange (reload) and stops when asked to.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/eto-a/porthole/internal/service"
)

func main() {
	name := flag.String("name", "", "service name")
	marker := flag.String("marker", "", "file that gets a line per reload")
	flag.Parse()

	err := service.RunService(*name, func(ctx context.Context, ready func(), reload <-chan struct{}) error {
		ready()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-reload:
				f, err := os.OpenFile(*marker, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
				if err != nil {
					return err
				}
				_, err = f.WriteString("reload\n")
				if cerr := f.Close(); err == nil {
					err = cerr
				}
				if err != nil {
					return err
				}
			}
		}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
