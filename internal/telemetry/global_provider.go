// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

var globalTelemetry atomic.Pointer[Provider]

func setGlobalTelemetryProvider(p *Provider) {
	globalTelemetry.Store(p)
}

// RecordSQLiteBusy records a SQLITE_BUSY observation when the default sidecar
// Provider has been registered (see NewProvider).
func RecordSQLiteBusy(ctx context.Context, operation string) {
	if p := globalTelemetry.Load(); p != nil {
		p.RecordSQLiteBusy(ctx, operation)
	}
}

// RecoverPanic executes fn; if fn panics, it records metrics + EventError and re-panics is false (swallowed).
// Pass subsystem for the panic counter label (e.g. SubsystemTelemetry).
func RecoverPanic(ctx context.Context, p *Provider, subsystem gatewaylog.Subsystem, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			if p != nil {
				p.RecordPanic(ctx, subsystem)
			}
		}
	}()
	fn()
}
