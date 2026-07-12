// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// InboundImportErrorCode is a fixed, payload-free request-scope failure.
type InboundImportErrorCode string

const (
	InboundImportInvalidInput   InboundImportErrorCode = "invalid_input"
	InboundImportUnavailable    InboundImportErrorCode = "unavailable"
	InboundImportClosed         InboundImportErrorCode = "closed"
	InboundImportFloorRejected  InboundImportErrorCode = "floor_rejected"
	InboundImportBuildRejected  InboundImportErrorCode = "build_rejected"
	InboundImportDeliveryFailed InboundImportErrorCode = "delivery_failed"
)

// InboundImportError never includes decoded OTLP values, attribute names,
// endpoints, or generated builder diagnostics.
type InboundImportError struct{ code InboundImportErrorCode }

func (err *InboundImportError) Error() string {
	if err == nil {
		return "inbound observability import failed"
	}
	return "inbound observability import failed: " + string(err.code)
}

func (err *InboundImportError) Code() InboundImportErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// InboundOptionalExportPolicy is a sealed, request-derived routing control for
// normalized inbound telemetry. Its zero value performs ordinary fan-out. An
// origin suppresses only that exact local destination; the terminal policy
// suppresses every optional export. Neither state is canonical record data.
type InboundOptionalExportPolicy struct {
	originDestination string
	suppressAll       bool
}

// NewInboundOriginDestination validates the local destination selected by the
// authenticated receiver decision. Empty or otherwise unbounded values fail
// before any imported builder can run.
func NewInboundOriginDestination(originDestination string) (InboundOptionalExportPolicy, error) {
	if !observability.IsStableToken(originDestination) {
		return InboundOptionalExportPolicy{}, &InboundImportError{code: InboundImportInvalidInput}
	}
	return InboundOptionalExportPolicy{originDestination: originDestination}, nil
}

// SuppressAllInboundOptionalExport is the sealed four-hop terminal state. It
// is intentionally not represented by a synthetic destination token.
func SuppressAllInboundOptionalExport() InboundOptionalExportPolicy {
	return InboundOptionalExportPolicy{suppressAll: true}
}

func (policy InboundOptionalExportPolicy) valid() bool {
	return (!policy.suppressAll || policy.originDestination == "") &&
		(policy.originDestination == "" || observability.IsStableToken(policy.originDestination))
}

// InboundImportBatch pins one immutable runtime generation for one decoded
// receiver request. Every leaf target is processed serially through this scope,
// so collection, generated construction, SQLite persistence, route projection,
// destination enqueue, and metric delivery cannot cross a reload generation.
//
// Callers MUST Close the batch before the request returns. The type deliberately
// exposes no graph, provider, plan, or lease and therefore cannot bypass normal
// collection or routing. It is not safe for reentrant use from a builder.
type InboundImportBatch struct {
	mu      sync.Mutex
	runtime *Runtime
	lease   *runtimegraph.Lease
	closed  bool
}

// BeginInboundImportBatch acquires the generation before any leaf collection or
// construction. A successful batch remains valid while a newer generation is
// published; old-generation retirement waits until Close.
func (runtime *Runtime) BeginInboundImportBatch(ctx context.Context) (*InboundImportBatch, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil {
		return nil, &InboundImportError{code: InboundImportInvalidInput}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	graph := lease.Graph()
	if graph == nil || graph.Plan() == nil || graph.Digest() == "" || graph.Generation() == 0 {
		lease.Release()
		return nil, &InboundImportError{code: InboundImportUnavailable}
	}
	return &InboundImportBatch{runtime: runtime, lease: lease}, nil
}

// EmitLog runs one imported log target through the ordinary local-first log
// pipeline on the pinned generation. The builder is invoked only after
// collection admits the target. Imported records are structurally barred from
// acquiring mandatory or floor-only state even if a caller selects a locally
// mandatory family descriptor.
func (batch *InboundImportBatch) EmitLog(
	ctx context.Context,
	metadata router.Metadata,
	builder EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return batch.EmitImportedLog(ctx, metadata, InboundOptionalExportPolicy{}, builder)
}

// EmitImportedLog preserves the mandatory SQLite-first log path while
// applying private inbound-only optional-export controls after persistence.
func (batch *InboundImportBatch) EmitImportedLog(
	ctx context.Context,
	metadata router.Metadata,
	policy InboundOptionalExportPolicy,
	builder EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	if batch == nil || ctx == nil || builder == nil || !policy.valid() {
		return pipeline.LocalLogOutcome{}, &InboundImportError{code: InboundImportInvalidInput}
	}
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.closed || batch.runtime == nil || batch.lease == nil {
		return pipeline.LocalLogOutcome{}, &InboundImportError{code: InboundImportClosed}
	}
	floorRejected := false
	outcome, err := batch.runtime.emitImportedWithLease(ctx, batch.lease, metadata, func(
		snapshot EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		record, err := builder(snapshot, admission)
		if err != nil {
			return observability.Record{}, err
		}
		if record.Signal() != observability.SignalLogs || record.Mandatory() || record.IsFloorOnly() {
			floorRejected = true
			return observability.Record{}, &InboundImportError{code: InboundImportFloorRejected}
		}
		return record, nil
	}, policy.originDestination, policy.suppressAll)
	if floorRejected {
		return outcome, &InboundImportError{code: InboundImportFloorRejected}
	}
	return outcome, err
}

// RecordGeneratedMetric applies the ordinary metric collection gate before the
// builder and synchronously records the resulting target on this batch's pinned
// provider generation. Disabled targets return an empty result without invoking
// the builder.
func (batch *InboundImportBatch) RecordGeneratedMetric(
	ctx context.Context,
	family observability.EventName,
	builder GeneratedMetricBuilder,
) (telemetry.V8MetricRecordResult, error) {
	if batch == nil || ctx == nil || family == "" || builder == nil ||
		!observability.IsRegisteredEventNameForSignal(observability.SignalMetrics, family) {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportInvalidInput}
	}
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.closed || batch.runtime == nil || batch.lease == nil {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportClosed}
	}
	return batch.runtime.recordGeneratedMetricWithLease(ctx, batch.lease, family, builder)
}

// Close releases the request generation exactly once. It is idempotent and may
// be called after a leaf error; leaf failures do not invalidate sibling targets.
func (batch *InboundImportBatch) Close() {
	if batch == nil {
		return
	}
	batch.mu.Lock()
	if batch.closed {
		batch.mu.Unlock()
		return
	}
	batch.closed = true
	lease := batch.lease
	batch.lease = nil
	batch.runtime = nil
	batch.mu.Unlock()
	lease.Release()
}

var _ error = (*InboundImportError)(nil)
