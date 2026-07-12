// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// InboundSignalBuilder performs typed mapping and private generated
// construction only after this request generation admits the exact target.
type InboundSignalBuilder func(EmitContext) (observability.Record, error)

// ImportTrace checks collection before invoking mapping/construction and then
// hands the exact imported topology directly to canonical trace consumers.
// It never creates a local SDK span and never enters the SQLite log pipeline.
func (batch *InboundImportBatch) ImportTrace(
	ctx context.Context,
	target observability.InboundTarget,
	authenticatedSource string,
	builder InboundSignalBuilder,
) (telemetry.V8ImportedSpanResult, error) {
	return batch.ImportTraceWithPolicy(
		ctx, target, authenticatedSource, InboundOptionalExportPolicy{}, builder,
	)
}

// ImportTraceWithPolicy applies imported-only loop and terminal-hop controls
// without placing either value in the canonical span or its attributes.
func (batch *InboundImportBatch) ImportTraceWithPolicy(
	ctx context.Context,
	target observability.InboundTarget,
	authenticatedSource string,
	policy InboundOptionalExportPolicy,
	builder InboundSignalBuilder,
) (telemetry.V8ImportedSpanResult, error) {
	if batch == nil || ctx == nil || builder == nil ||
		target.Signal() != observability.SignalTraces ||
		target.Role() != observability.InboundTargetImport ||
		!target.AcceptsAuthenticatedSource(authenticatedSource) || !policy.valid() {
		return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportInvalidInput}
	}
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.closed || batch.runtime == nil || batch.lease == nil {
		return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportClosed}
	}
	graph := batch.lease.Graph()
	if graph == nil {
		return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	if !inboundTargetCollected(graph.Plan(), target) {
		return telemetry.V8ImportedSpanResult{}, nil
	}
	if err := ctx.Err(); err != nil {
		return telemetry.V8ImportedSpanResult{}, err
	}
	provider, ok := telemetry.V8ProviderFromLease(batch.lease)
	if !ok {
		return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	digest, generation, bound := provider.V8PlanBinding()
	if !bound || digest == "" || digest != graph.Digest() || generation != graph.Generation() {
		return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	// Collection precedes the caller callback, so disabled targets cannot map
	// fields, allocate a canonical record ID, or reach any destination.
	if !provider.TraceBucketEnabled(target.Bucket()) {
		return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	resourceContext, ok := provider.V8ResourceContext()
	if !ok {
		return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	localResource, err := inboundLocalTraceResource(target, resourceContext)
	if err != nil {
		return telemetry.V8ImportedSpanResult{}, err
	}
	resourceFields := resourceContext.TraceResourceFields()
	snapshot := EmitContext{
		plan: graph.Plan(), digest: digest, generation: generation,
		inboundTraceResource: localResource,
		inboundTraceReady:    true,
		inboundBinaryVersion: resourceContext.ServiceVersion(),
		inboundInstanceID:    resourceFields.DefenseClawInstanceID,
	}
	record, err := builder(snapshot)
	if err != nil || !validInboundSignalRecord(
		record, target, authenticatedSource, digest, generation, observability.ImportModeImport,
	) {
		return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportBuildRejected}
	}
	// Imported trace fan-out is a bounded, synchronous TryEnqueue operation;
	// unlike metric recording it deliberately has no transport context. Honor
	// cancellation at both request boundaries so a builder cannot enqueue after
	// its caller has gone away.
	if err := ctx.Err(); err != nil {
		return telemetry.V8ImportedSpanResult{}, err
	}
	exportPolicy := telemetry.SuppressAllV8ImportedExport()
	var policyErr error
	if !policy.suppressAll {
		exportPolicy, policyErr = telemetry.NewV8ImportedExportPolicy(policy.originDestination)
		if policyErr != nil {
			return telemetry.V8ImportedSpanResult{}, &InboundImportError{code: InboundImportInvalidInput}
		}
	}
	result, err := provider.ImportV8CanonicalSpanWithPolicy(record, exportPolicy)
	if err != nil {
		return result, &InboundImportError{code: InboundImportDeliveryFailed}
	}
	return result, nil
}

// RecordMetric checks the exact generated metric target before typed mapping
// and records it on the pinned generation. Metrics never enter SQLite.
func (batch *InboundImportBatch) RecordMetric(
	ctx context.Context,
	target observability.InboundTarget,
	authenticatedSource string,
	builder InboundSignalBuilder,
) (telemetry.V8MetricRecordResult, error) {
	return batch.RecordMetricWithPolicy(
		ctx, target, authenticatedSource, InboundOptionalExportPolicy{}, builder,
	)
}

// RecordMetricWithPolicy applies imported-only loop and terminal-hop controls
// without adding them to the metric record or projected labels.
func (batch *InboundImportBatch) RecordMetricWithPolicy(
	ctx context.Context,
	target observability.InboundTarget,
	authenticatedSource string,
	policy InboundOptionalExportPolicy,
	builder InboundSignalBuilder,
) (telemetry.V8MetricRecordResult, error) {
	if batch == nil || ctx == nil || builder == nil ||
		target.Signal() != observability.SignalMetrics ||
		(target.Role() != observability.InboundTargetImport && target.Role() != observability.InboundTargetDerive) ||
		!target.AcceptsAuthenticatedSource(authenticatedSource) || !policy.valid() {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportInvalidInput}
	}
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.closed || batch.runtime == nil || batch.lease == nil {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportClosed}
	}
	graph := batch.lease.Graph()
	if graph == nil {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	if !inboundTargetCollected(graph.Plan(), target) {
		return telemetry.V8MetricRecordResult{}, nil
	}
	provider, ok := telemetry.V8ProviderFromLease(batch.lease)
	if !ok {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	digest, generation, bound := provider.V8PlanBinding()
	if !bound || digest == "" || digest != graph.Digest() || generation != graph.Generation() {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	if !provider.MetricFamilyEnabled(target.EventName()) {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	resourceContext, ok := provider.V8ResourceContext()
	if !ok {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportUnavailable}
	}
	snapshot := EmitContext{
		plan: graph.Plan(), digest: digest, generation: generation,
		inboundBinaryVersion: resourceContext.ServiceVersion(),
		inboundInstanceID:    resourceContext.TraceResourceFields().DefenseClawInstanceID,
	}
	record, err := builder(snapshot)
	wantMode := observability.ImportModeImport
	if target.Role() == observability.InboundTargetDerive {
		wantMode = observability.ImportModeDerive
	}
	if err != nil || !validInboundSignalRecord(
		record, target, authenticatedSource, digest, generation, wantMode,
	) {
		return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportBuildRejected}
	}
	exportPolicy := telemetry.SuppressAllV8ImportedExport()
	var policyErr error
	if !policy.suppressAll {
		exportPolicy, policyErr = telemetry.NewV8ImportedExportPolicy(policy.originDestination)
		if policyErr != nil {
			return telemetry.V8MetricRecordResult{}, &InboundImportError{code: InboundImportInvalidInput}
		}
	}
	result, err := provider.RecordImportedMetric(ctx, record, exportPolicy)
	if err != nil {
		return result, &InboundImportError{code: InboundImportDeliveryFailed}
	}
	return result, nil
}

func inboundLocalTraceResource(
	target observability.InboundTarget,
	resource telemetry.V8ResourceContext,
) (observability.InboundLocalTraceResource, error) {
	values := resource.Values()
	mapped := make([]observability.InboundMappedField, 0, len(values))
	for _, field := range target.TraceResourceFields() {
		value := values[field.FieldRef()]
		if value == "" {
			continue
		}
		kind, supported := target.MappedValueKind(field)
		if !supported {
			continue
		}
		if kind != observability.InboundMappedValueString {
			return observability.InboundLocalTraceResource{}, &InboundImportError{code: InboundImportBuildRejected}
		}
		mapped = append(mapped, observability.NewInboundMappedString(field, value))
	}
	sealed, err := observability.NewInboundLocalTraceResourceWithCustom(
		target, mapped, resource.CustomResourceAttributes(),
	)
	if err != nil {
		return observability.InboundLocalTraceResource{}, &InboundImportError{code: InboundImportBuildRejected}
	}
	return sealed, nil
}

func inboundTargetCollected(
	plan *config.ObservabilityV8Plan,
	target observability.InboundTarget,
) bool {
	if plan == nil {
		return false
	}
	for _, bucket := range plan.Snapshot().Buckets {
		if bucket.Bucket == target.Bucket() {
			return bucket.Collect.Enabled(target.Signal())
		}
	}
	return false
}

func validInboundSignalRecord(
	record observability.Record,
	target observability.InboundTarget,
	authenticatedSource, digest string,
	generation uint64,
	wantMode observability.ImportMode,
) bool {
	if record.Signal() != target.Signal() || record.Bucket() != target.Bucket() ||
		record.EventName() != target.EventName() || record.Source() != observability.SourceOTelReceiver ||
		record.Connector() != authenticatedSource || record.Mandatory() || record.IsFloorOnly() ||
		!record.SchemaDerivedFieldClasses() {
		return false
	}
	provenance := record.Provenance()
	return provenance.ConfigGeneration >= 0 && uint64(provenance.ConfigGeneration) == generation &&
		provenance.ConfigDigest == digest && provenance.Import != nil &&
		provenance.Import.BindingID == target.MatchID() &&
		provenance.Import.AuthenticatedSource == authenticatedSource &&
		provenance.Import.Mode == wantMode
}
