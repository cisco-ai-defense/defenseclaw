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

// RecordJudgePersistDrop records a queue-overflow drop on the
// global Provider when one is registered. Mirrors RecordSQLiteBusy
// so call sites in internal/gateway/judge_store.go do not need to
// import or thread the Provider explicitly.
func RecordJudgePersistDrop(ctx context.Context, reason string) {
	if p := globalTelemetry.Load(); p != nil {
		p.RecordJudgePersistDrop(ctx, reason)
	}
}

// RecordJudgePersistQueueDepth snapshots the queue gauge on the
// global Provider.
func RecordJudgePersistQueueDepth(ctx context.Context, depth int64) {
	if p := globalTelemetry.Load(); p != nil {
		p.RecordJudgePersistQueueDepth(ctx, depth)
	}
}

// RecordJudgePersistBatchSize records a committed batch size on
// the global Provider.
func RecordJudgePersistBatchSize(ctx context.Context, n int64) {
	if p := globalTelemetry.Load(); p != nil {
		p.RecordJudgePersistBatchSize(ctx, n)
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
