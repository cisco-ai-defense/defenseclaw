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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
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
