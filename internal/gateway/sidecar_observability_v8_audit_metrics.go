// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// RecordRuntimeV8GeneratedMetric adapts audit's opaque generated-metric
// capability to the runtime without exposing the graph or telemetry provider
// across the package boundary. Runtime validates the family identity and exact
// generation/digest again before recording.
func (owner *sidecarOwnedObservabilityV8Runtime) RecordRuntimeV8GeneratedMetric(
	ctx context.Context,
	metric audit.RuntimeV8GeneratedMetric,
) error {
	_, err := owner.RecordGeneratedMetric(
		ctx,
		metric.Family(),
		func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			return metric.Build(audit.RuntimeV8BuildContext{
				ConfigGeneration: snapshot.Generation(),
				ConfigDigest:     snapshot.Digest(),
			})
		},
	)
	return err
}

// RecordRuntimeV8GeneratedMetricBatch preserves one graph generation across
// related audit metrics (for example the persisted-event counter plus activity
// count and diff-size observations). Every operation remains sealed by audit
// and is identity-checked both before and after construction.
func (owner *sidecarOwnedObservabilityV8Runtime) RecordRuntimeV8GeneratedMetricBatch(
	ctx context.Context,
	metrics []audit.RuntimeV8GeneratedMetric,
) error {
	if owner == nil || ctx == nil || len(metrics) == 0 ||
		len(metrics) > observabilityruntime.MaxGeneratedMetricBatchItems {
		return &sidecarObservabilityError{code: sidecarObservabilityEmitFailed}
	}
	items := make([]observabilityruntime.GeneratedMetricBatchItem, len(metrics))
	for index, metric := range metrics {
		metric := metric
		if metric.Family() == "" {
			return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		items[index] = observabilityruntime.GeneratedMetricBatchItem{
			Family: metric.Family(),
			Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
				return metric.Build(audit.RuntimeV8BuildContext{
					ConfigGeneration: snapshot.Generation(),
					ConfigDigest:     snapshot.Digest(),
				})
			},
		}
	}
	_, err := owner.RecordGeneratedMetricBatch(ctx, items)
	return err
}

var _ audit.RuntimeV8MetricEmitter = (*sidecarOwnedObservabilityV8Runtime)(nil)
var _ audit.RuntimeV8MetricBatchEmitter = (*sidecarOwnedObservabilityV8Runtime)(nil)
