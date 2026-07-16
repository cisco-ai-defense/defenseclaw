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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// GeneratedMetricErrorCode is a fixed, content-free recording failure.
type GeneratedMetricErrorCode string

const (
	GeneratedMetricInvalidInput  GeneratedMetricErrorCode = "invalid_input"
	GeneratedMetricUnavailable   GeneratedMetricErrorCode = "unavailable"
	GeneratedMetricBuildRejected GeneratedMetricErrorCode = "build_rejected"
	GeneratedMetricRecordFailed  GeneratedMetricErrorCode = "record_failed"
)

type GeneratedMetricError struct{ code GeneratedMetricErrorCode }

func (err *GeneratedMetricError) Error() string {
	if err == nil {
		return "generated metric operation failed"
	}
	return "generated metric operation failed: " + string(err.code)
}

func (err *GeneratedMetricError) Code() GeneratedMetricErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// GeneratedMetricBuilder runs only after the exact family bucket is collected.
// The supplied graph snapshot must be used for generated provenance.
type GeneratedMetricBuilder func(EmitContext) (observability.Record, error)

const MaxGeneratedMetricBatchItems = 65_536

// GeneratedMetricBatchItem is one exact generated family occurrence in a
// request-bounded metric group. A batch is not a transaction at remote sinks;
// its guarantee is that collection, construction, and delivery for every item
// use the same immutable runtime generation and lease.
type GeneratedMetricBatchItem struct {
	Family  observability.EventName
	Builder GeneratedMetricBuilder
}

// GeneratedMetricFamilyEnabled reports the collection gate for one generated
// family in the exact graph generation held for this call. It exists for
// producers whose observation cardinality is itself dynamic (for example one
// exporter-health point per configured destination and signal), so they can
// avoid taking the underlying snapshot when collection is disabled. Record
// construction and delivery still go through RecordGeneratedMetricBatch.
func (runtime *Runtime) GeneratedMetricFamilyEnabled(
	ctx context.Context,
	family observability.EventName,
) (bool, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || family == "" ||
		!observability.IsRegisteredEventNameForSignal(observability.SignalMetrics, family) {
		return false, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	graph := lease.Graph()
	provider, ok := telemetry.V8ProviderFromLease(lease)
	if graph == nil || !ok {
		return false, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	digest, generation, bound := provider.V8PlanBinding()
	if !bound || digest == "" || digest != graph.Digest() || generation != graph.Generation() {
		return false, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	return provider.MetricFamilyEnabled(family), nil
}

// RecordGeneratedMetric holds one runtimegraph lease across collection gating,
// generated construction, projection, and synchronous destination handoff.
// A disabled family returns an empty result without invoking builder.
func (runtime *Runtime) RecordGeneratedMetric(
	ctx context.Context,
	family observability.EventName,
	builder GeneratedMetricBuilder,
) (telemetry.V8MetricRecordResult, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || family == "" || builder == nil ||
		!observability.IsRegisteredEventNameForSignal(observability.SignalMetrics, family) {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return telemetry.V8MetricRecordResult{}, err
	}
	defer lease.Release()
	return recordGeneratedMetricWithLease(
		ctx, lease, runtime.store, family, builder,
		correlationDefaultsFromContext(ctx, correlationDefaultsGenerated),
	)
}

// RecordGeneratedMetricBatch pins one runtime generation across a bounded
// group of related metric observations. Each family retains its independent
// collection gate, so a disabled family never invokes its builder. Delivery is
// sequential and truthful: results before a failure describe already-attempted
// occurrences, and no later builder runs after the first failure.
func (runtime *Runtime) RecordGeneratedMetricBatch(
	ctx context.Context,
	items []GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || len(items) == 0 ||
		len(items) > MaxGeneratedMetricBatchItems {
		return nil, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	if err := validateGeneratedMetricBatchItems(items); err != nil {
		return nil, err
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	results := make([]telemetry.V8MetricRecordResult, len(items))
	for index, item := range items {
		result, recordErr := recordGeneratedMetricWithLease(
			ctx, lease, runtime.store, item.Family, item.Builder,
			correlationDefaultsFromContext(ctx, correlationDefaultsGenerated),
		)
		results[index] = result
		if recordErr != nil {
			return results, recordErr
		}
	}
	return results, nil
}

func validateGeneratedMetricBatchItems(items []GeneratedMetricBatchItem) error {
	if len(items) == 0 || len(items) > MaxGeneratedMetricBatchItems {
		return &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	for _, item := range items {
		if item.Family == "" || item.Builder == nil ||
			!observability.IsRegisteredEventNameForSignal(observability.SignalMetrics, item.Family) {
			return &GeneratedMetricError{code: GeneratedMetricInvalidInput}
		}
	}
	return nil
}

func recordGeneratedMetricWithLease(
	ctx context.Context,
	lease *runtimegraph.Lease,
	store *audit.Store,
	family observability.EventName,
	builder GeneratedMetricBuilder,
	correlationDefaults observability.Correlation,
) (telemetry.V8MetricRecordResult, error) {
	if ctx == nil || lease == nil || family == "" || builder == nil ||
		!observability.IsRegisteredEventNameForSignal(observability.SignalMetrics, family) {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	graph := lease.Graph()
	provider, ok := telemetry.V8ProviderFromLease(lease)
	if graph == nil || !ok {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	digest, generation, bound := provider.V8PlanBinding()
	if !bound || digest == "" || digest != graph.Digest() || generation != graph.Generation() {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	// This check deliberately precedes the producer callback so disabled
	// collection cannot construct labels, records, or expensive measurements.
	if !provider.MetricFamilyEnabled(family) {
		return telemetry.V8MetricRecordResult{}, nil
	}
	snapshot := EmitContext{plan: graph.Plan(), digest: digest, generation: generation}
	record, buildErr := builder(snapshot)
	if buildErr != nil {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricBuildRejected}
	}
	record, buildErr = stampRuntimeCorrelation(record, correlationDefaults)
	if buildErr != nil {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricBuildRejected}
	}
	provenance := record.Provenance()
	if record.Signal() != observability.SignalMetrics || record.EventName() != family ||
		provenance.ConfigGeneration < 0 || uint64(provenance.ConfigGeneration) != generation ||
		provenance.ConfigDigest != digest {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricBuildRejected}
	}
	if err := persistRuntimeCorrelationObservation(ctx, store, record); err != nil {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricRecordFailed}
	}
	result, recordErr := provider.RecordGeneratedMetric(ctx, record)
	if recordErr != nil {
		return result, &GeneratedMetricError{code: GeneratedMetricRecordFailed}
	}
	return result, nil
}

// recordGeneratedMetricWithLease preserves the private runtime/batch seam for
// imported occurrences while trace-owned siblings call the lease helper
// directly. The runtime receiver remains the owner check at those call sites.
func (runtime *Runtime) recordGeneratedMetricWithLease(
	ctx context.Context,
	lease *runtimegraph.Lease,
	family observability.EventName,
	builder GeneratedMetricBuilder,
	defaultMode correlationDefaultMode,
) (telemetry.V8MetricRecordResult, error) {
	if runtime == nil {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	return recordGeneratedMetricWithLease(
		ctx, lease, runtime.store, family, builder, correlationDefaultsFromContext(ctx, defaultMode),
	)
}

var _ error = (*GeneratedMetricError)(nil)
