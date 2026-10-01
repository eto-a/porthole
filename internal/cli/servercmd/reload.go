// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package servercmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
)

// watchReload calls reload every time one of reloadSignals arrives, until ctx is done or the returned stop
// function is called. It is a no-op on platforms without such signals. Notify is registered before it returns,
// so a signal sent right after watchReload does not hit the default action (terminate, for SIGHUP).
func watchReload(ctx context.Context, log *slog.Logger, reload func() error) (stop func()) {
	sigs := reloadSignals()
	if len(sigs) == 0 {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	done := make(chan struct{})
	go func() {
		defer close(done)
		reloadLoop(ctx, log, ch, reload)
	}()
	return func() {
		signal.Stop(ch)
		cancel()
		<-done
	}
}

// reloadLoop runs reload for every value received from trigger until ctx is done. reload reports its own
// outcome in the log, so its error is not logged again here.
func reloadLoop(ctx context.Context, log *slog.Logger, trigger <-chan os.Signal, reload func() error) {
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-trigger:
			log.Info("reloading tls certificate", "signal", sig.String())
			_ = reload()
		}
	}
}
