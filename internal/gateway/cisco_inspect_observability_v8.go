// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const ciscoInspectV8Producer = "gateway.cisco_ai_defense"

type ciscoInspectMetricRuntimeContextKey struct{}

// recordCiscoInspectV8 emits one HTTP-attempt latency observation and, when
// code is non-empty, its matching error counter under one runtime generation.
// A negative elapsed duration intentionally suppresses latency for failures
// that occurred before an HTTP attempt existed.
func recordCiscoInspectV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	elapsed time.Duration,
	outcome observability.Outcome,
	code gatewaylog.ErrorCode,
) {
	if ctx == nil || runtime == nil {
		return
	}
	observedAt := time.Now().UTC()
	connector := hookDecisionMetricConnector(audit.EnvelopeFromContext(ctx).Connector)
	meta := hookDecisionMetricMeta(ctx, connector)
	item := func(
		family string,
		build hookV8MetricRecordBuilder,
	) observabilityruntime.GeneratedMetricBatchItem {
		return newHookV8MetricBatchItemForProducer(
			ctx, observedAt, meta, ciscoInspectV8Producer, observability.EventName(family), build,
		)
	}
	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 3)
	if elapsed >= 0 {
		elapsedMs := float64(elapsed) / float64(time.Millisecond)
		if !math.IsNaN(elapsedMs) && !math.IsInf(elapsedMs, 0) {
			items = append(items, item(
				observability.TelemetryInstrumentDefenseClawCiscoInspectLatency,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawCiscoInspectLatency(
						observability.MetricDefenseClawCiscoInspectLatencyInput{
							Envelope: envelope, Value: elapsedMs,
							DefenseClawOutcome: observability.Present(string(outcome)),
						},
					)
				},
			))
		}
	}
	if code != "" {
		items = append(items, item(
			observability.TelemetryInstrumentDefenseClawCiscoErrors,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawCiscoErrors(observability.MetricDefenseClawCiscoErrorsInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricCode: observability.Present(string(code)),
				})
			},
		))
		items = append(items, gatewayErrorMetricItem(
			ctx, observedAt, string(gatewaylog.SubsystemCiscoInspect), string(code),
		))
	}
	if len(items) > 0 {
		_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
	}
}
