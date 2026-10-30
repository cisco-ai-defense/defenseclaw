// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// IPCRunner is the minimal shape the sidecar needs from the local
// UDS gRPC server (implemented by *internal/ipc.Server). It's
// declared here to keep the runtime-vs-transport boundary explicit
// and — importantly — to avoid an import cycle: internal/ipc already
// imports internal/gateway for SidecarHealth, so the reverse
// dependency has to be pulled through this interface.
type IPCRunner interface {
	// Run binds the UDS listener, serves gRPC, and blocks until ctx
	// is cancelled. Returns a non-nil error on bind / permission /
	// serve failure. Clean shutdown returns nil.
	Run(ctx context.Context) error
}

// SetIPCRunner installs the concrete IPC server on the sidecar. Must
// be called before Run. Passing nil disables the IPC goroutine.
func (s *Sidecar) SetIPCRunner(r IPCRunner) {
	if s == nil {
		return
	}
	s.ipcRunner = r
}

type ipcServingHookKey struct{}

// MarkIPCServing is called by an IPCRunner once its listener is bound and it
// has started serving. runIPCWithRetry uses it to reset its backoff, so a
// server that served and later failed is retried at the initial delay instead
// of inheriting the backoff its earlier failed binds built up. A no-op for a
// context that runIPCWithRetry did not create.
func MarkIPCServing(ctx context.Context) {
	if ctx == nil {
		return
	}
	if hook, ok := ctx.Value(ipcServingHookKey{}).(func()); ok && hook != nil {
		hook()
	}
}

// ipcRetryInitialDelay and ipcRetryMaxDelay bound the backoff between IPC
// server attempts. Variables so tests can shorten them.
var (
	ipcRetryInitialDelay = 15 * time.Second
	ipcRetryMaxDelay     = 5 * time.Minute
)

// runIPCWithRetry keeps the local IPC server running without making it a
// subsystem the gateway exits for. A failed bind is most often permission
// drift on the IPC folder (icacls /reset on the install tree removes the
// gateway's entry, and the gateway's write-restricted token cannot re-ACL the
// folder); exiting would only crash-loop the gateway and take enforcement
// down with it. The gateway runs degraded instead, its IPC health reports the
// error, and the server is retried with a bounded backoff until a privileged
// component (the guardian or the installer) has repaired the folder.
func (s *Sidecar) runIPCWithRetry(ctx context.Context) {
	delay := ipcRetryInitialDelay
	var served atomic.Bool
	runCtx := context.WithValue(ctx, ipcServingHookKey{}, func() { served.Store(true) })
	for {
		served.Store(false)
		err := s.ipcRunner.Run(runCtx)
		if ctx.Err() != nil {
			return
		}
		// Back off only across consecutive attempts that never served: a
		// server that bound and served restarts the schedule.
		if err == nil || served.Load() {
			delay = ipcRetryInitialDelay
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] ipc server exited with error: %v\n", err)
			managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
				"subsystem": "ipc",
				"reason":    err.Error(),
				"action":    fmt.Sprintf("retry in %s", delay),
			})
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay *= 2; delay > ipcRetryMaxDelay {
			delay = ipcRetryMaxDelay
		}
	}
}

// OSNotifier returns the notifier.Dispatcher owned by this sidecar
// so the CLI wiring layer can register additional observers (e.g.
// the AVC IPC bridge) after construction.
func (s *Sidecar) OSNotifier() *notifier.Dispatcher {
	if s == nil {
		return nil
	}
	return s.osNotifier
}

// AuditStore exposes the audit store for read-only consumers (the
// IPC stats source among them). Kept alongside SetIPCRunner because
// the two go together in the CLI wiring path — see internal/cli.
func (s *Sidecar) AuditStore() *audit.Store {
	if s == nil {
		return nil
	}
	return s.store
}
