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
	results, recordErr := recordGeneratedMetricsWithLease(
		ctx, lease, runtime.store, []GeneratedMetricBatchItem{{Family: family, Builder: builder}},
		correlationDefaultsFromContext(ctx, correlationDefaultsGenerated),
	)
	return results[0], recordErr
}

// RecordGeneratedMetricBatch pins one runtime generation across a bounded
// group of related metric observations. Each family retains its independent
// collection gate, so a disabled family never invokes its builder. Delivery is
// sequential and truthful: results before a failure describe already-attempted
// occurrences, and no later builder runs after the first build failure.
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
	return recordGeneratedMetricsWithLease(
		ctx, lease, runtime.store, items, correlationDefaultsFromContext(ctx, correlationDefaultsGenerated),
	)
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

// preparedGeneratedMetric is one built and checked metric record of a batch,
// waiting for its correlation observation to commit before the provider gets
// it. observed is false for a record without correlation, which has nothing
// to commit.
type preparedGeneratedMetric struct {
	index       int
	provider    *telemetry.Provider
	record      observability.Record
	observation audit.CorrelationObservation
	observed    bool
}

// recordGeneratedMetricsWithLease records a batch on one lease, in three
// steps. Every item is gated, built and checked in order, and no builder runs
// after the first item that fails. Then the correlation observations of the
// built records commit in one audit transaction. Only then does the provider
// get the records, in order (commit before export).
//
// One transaction per batch instead of one per metric is the B-26 write cut:
// a Claude Code PreToolUse records 13 generated metrics in a few batches,
// and each metric was a commit of its own that wrote a table page
// and the 11 index pages of correlation_observations to the audit WAL. If the
// group commit fails, the built records are recorded one at a time as before,
// so a failure stops at the same item, with the same results and the same
// records exported before it; only the builders of the later items, which
// build records and nothing else, have already run.
func recordGeneratedMetricsWithLease(
	ctx context.Context,
	lease *runtimegraph.Lease,
	store *audit.Store,
	items []GeneratedMetricBatchItem,
	correlationDefaults observability.Correlation,
) ([]telemetry.V8MetricRecordResult, error) {
	results := make([]telemetry.V8MetricRecordResult, len(items))
	prepared := make([]preparedGeneratedMetric, 0, len(items))
	var buildErr error
	for index, item := range items {
		metric, enabled, err := prepareGeneratedMetricWithLease(
			ctx, lease, store, item.Family, item.Builder, correlationDefaults,
		)
		if err != nil {
			buildErr = err
			break
		}
		if enabled {
			metric.index = index
			prepared = append(prepared, metric)
		}
	}
	observations := make([]audit.CorrelationObservation, 0, len(prepared))
	for _, metric := range prepared {
		if metric.observed {
			observations = append(observations, metric.observation)
		}
	}
	if len(observations) > 0 {
		if groupErr := recordRuntimeCorrelationObservations(ctx, store, observations...); groupErr != nil {
			for _, metric := range prepared {
				if metric.observed {
					if recordErr := recordRuntimeCorrelationObservations(ctx, store, metric.observation); recordErr != nil {
						return results, &GeneratedMetricError{code: GeneratedMetricRecordFailed}
					}
				}
				if exportErr := exportPreparedGeneratedMetric(ctx, metric, results); exportErr != nil {
					return results, exportErr
				}
			}
			return results, buildErr
		}
	}
	if len(observations) > 0 && audit.CallWritesOpen(ctx, store) {
		// The observations wait in the hook call's batch: the provider gets
		// the records after the call commits them (commit before export).
		if fork := lease.Fork(); fork != nil {
			exportCtx := context.WithoutCancel(ctx)
			deferred := append([]preparedGeneratedMetric(nil), prepared...)
			if audit.DeferAfterCallWrites(ctx, store, func() {
				defer fork.Release()
				scratch := make([]telemetry.V8MetricRecordResult, len(items))
				for _, metric := range deferred {
					if exportPreparedGeneratedMetric(exportCtx, metric, scratch) != nil {
						return
					}
				}
			}) {
				return results, buildErr
			}
			fork.Release()
		}
	}
	for _, metric := range prepared {
		if err := exportPreparedGeneratedMetric(ctx, metric, results); err != nil {
			return results, err
		}
	}
	return results, buildErr
}

// prepareGeneratedMetricWithLease runs the collection gate, the builder and
// the provenance checks of one item. enabled is false for a disabled family,
// whose builder never runs.
func prepareGeneratedMetricWithLease(
	ctx context.Context,
	lease *runtimegraph.Lease,
	store *audit.Store,
	family observability.EventName,
	builder GeneratedMetricBuilder,
	correlationDefaults observability.Correlation,
) (preparedGeneratedMetric, bool, error) {
	if ctx == nil || lease == nil || family == "" || builder == nil ||
		!observability.IsRegisteredEventNameForSignal(observability.SignalMetrics, family) {
		return preparedGeneratedMetric{}, false, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	graph := lease.Graph()
	provider, ok := telemetry.V8ProviderFromLease(lease)
	if graph == nil || !ok {
		return preparedGeneratedMetric{}, false, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	digest, generation, bound := provider.V8PlanBinding()
	if !bound || digest == "" || digest != graph.Digest() || generation != graph.Generation() {
		return preparedGeneratedMetric{}, false, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	// This check deliberately precedes the producer callback so disabled
	// collection cannot construct labels, records, or expensive measurements.
	if !provider.MetricFamilyEnabled(family) {
		return preparedGeneratedMetric{}, false, nil
	}
	snapshot := EmitContext{plan: graph.Plan(), digest: digest, generation: generation}
	record, buildErr := builder(snapshot)
	if buildErr != nil {
		return preparedGeneratedMetric{}, false, &GeneratedMetricError{code: GeneratedMetricBuildRejected}
	}
	record, buildErr = stampRuntimeCorrelation(record, correlationDefaults)
	if buildErr != nil {
		return preparedGeneratedMetric{}, false, &GeneratedMetricError{code: GeneratedMetricBuildRejected}
	}
	provenance := record.Provenance()
	if record.Signal() != observability.SignalMetrics || record.EventName() != family ||
		provenance.ConfigGeneration < 0 || uint64(provenance.ConfigGeneration) != generation ||
		provenance.ConfigDigest != digest {
		return preparedGeneratedMetric{}, false, &GeneratedMetricError{code: GeneratedMetricBuildRejected}
	}
	observation, observed, err := runtimeCorrelationObservationFor(store, record)
	if err != nil {
		return preparedGeneratedMetric{}, false, &GeneratedMetricError{code: GeneratedMetricRecordFailed}
	}
	return preparedGeneratedMetric{
		provider: provider, record: record, observation: observation, observed: observed,
	}, true, nil
}

func exportPreparedGeneratedMetric(
	ctx context.Context,
	metric preparedGeneratedMetric,
	results []telemetry.V8MetricRecordResult,
) error {
	result, err := metric.provider.RecordGeneratedMetric(ctx, metric.record)
	results[metric.index] = result
	if err != nil {
		return &GeneratedMetricError{code: GeneratedMetricRecordFailed}
	}
	return nil
}

// recordGeneratedMetricWithLease preserves the private runtime seam for
// imported occurrences. The runtime receiver remains the owner check at that
// call site.
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
	results, err := recordGeneratedMetricsWithLease(
		ctx, lease, runtime.store, []GeneratedMetricBatchItem{{Family: family, Builder: builder}},
		correlationDefaultsFromContext(ctx, defaultMode),
	)
	return results[0], err
}

var _ error = (*GeneratedMetricError)(nil)
