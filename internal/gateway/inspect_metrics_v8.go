// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const inspectMetricsV8Producer = "gateway.inspect.metrics"

const trustedParserUncertaintyMetricScanner = "action-parser-uncertainty"

// recordInspectMetricsV8 is the generated-family owner for inspect and
// guardrail evaluation metrics emitted by the HTTP inspection surfaces. The
// local-observability projection keeps the established Prometheus names and
// labels while the canonical record retains W3C and DefenseClaw correlation.
func (a *APIServer) recordInspectMetricsV8(
	ctx context.Context,
	connectorName string,
	tool string,
	action string,
	rawSeverity string,
	elapsed time.Duration,
) {
	if a == nil || ctx == nil {
		return
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return
	}
	connectorName = hookDecisionMetricConnector(connectorName)
	tool = telemetry.NormalizeMetricTextLabel(tool)
	action = normalizeInspectMetricAction(action)
	severity := observability.NormalizeSeverity(firstNonEmpty(rawSeverity, "NONE"))
	if !severity.Valid || !severity.Present {
		return
	}
	latencyMillis := float64(elapsed) / float64(time.Millisecond)
	if latencyMillis < 0 {
		latencyMillis = 0
	}

	meta := hookDecisionMetricMeta(ctx, connectorName)
	meta.Source = connectorName
	observedAt := time.Now().UTC()
	item := func(
		family string,
		build hookV8MetricRecordBuilder,
	) observabilityruntime.GeneratedMetricBatchItem {
		return newHookV8MetricBatchItemForProducer(
			ctx, observedAt, meta, inspectMetricsV8Producer,
			observability.EventName(family), build,
		)
	}
	items := []observabilityruntime.GeneratedMetricBatchItem{
		item(observability.TelemetryInstrumentDefenseClawInspectEvaluations,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawInspectEvaluations(
					observability.MetricDefenseClawInspectEvaluationsInput{
						Envelope: envelope, Value: 1,
						DefenseClawMetricAction:     observability.Present(action),
						DefenseClawConnectorSource:  observability.Present(connectorName),
						DefenseClawSecuritySeverity: observability.Present(string(severity.Severity)),
						DefenseClawMetricTool:       observability.Present(tool),
					},
				)
			}),
		item(observability.TelemetryInstrumentDefenseClawInspectLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawInspectLatency(
					observability.MetricDefenseClawInspectLatencyInput{
						Envelope: envelope, Value: latencyMillis,
						DefenseClawConnectorSource: observability.Present(connectorName),
						DefenseClawMetricTool:      observability.Present(tool),
					},
				)
			}),
	}

	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

func (a *APIServer) recordGuardrailMetricsV8(
	ctx context.Context,
	connectorName string,
	scanner string,
	action string,
	elapsed time.Duration,
) {
	if a == nil || ctx == nil {
		return
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return
	}
	connectorName = hookDecisionMetricConnector(connectorName)
	scanner = telemetry.NormalizeMetricTextLabel(scanner)
	if scanner == "unknown" {
		return
	}
	action = normalizeInspectMetricAction(action)
	latencyMillis := float64(elapsed) / float64(time.Millisecond)
	if latencyMillis < 0 {
		latencyMillis = 0
	}

	meta := hookDecisionMetricMeta(ctx, connectorName)
	meta.Source = connectorName
	observedAt := time.Now().UTC()
	item := func(
		family string,
		build hookV8MetricRecordBuilder,
	) observabilityruntime.GeneratedMetricBatchItem {
		return newHookV8MetricBatchItemForProducer(
			ctx, observedAt, meta, inspectMetricsV8Producer,
			observability.EventName(family), build,
		)
	}
	items := []observabilityruntime.GeneratedMetricBatchItem{
		item(observability.TelemetryInstrumentDefenseClawGuardrailEvaluations,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawGuardrailEvaluations(
					observability.MetricDefenseClawGuardrailEvaluationsInput{
						Envelope: envelope, Value: 1,
						DefenseClawGuardrailEffectiveAction: observability.Present(action),
						DefenseClawConnectorSource:          observability.Present(connectorName),
						DefenseClawMetricGuardrailScanner:   observability.Present(scanner),
					},
				)
			}),
		item(observability.TelemetryInstrumentDefenseClawGuardrailLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawGuardrailLatency(
					observability.MetricDefenseClawGuardrailLatencyInput{
						Envelope: envelope, Value: latencyMillis,
						DefenseClawConnectorSource:        observability.Present(connectorName),
						DefenseClawMetricGuardrailScanner: observability.Present(scanner),
					},
				)
			}),
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

// recordParserUncertaintyMetricV8 records parser uncertainty as a value-free
// counter only. It intentionally emits neither a finding nor an alert metric:
// incomplete shell projection is an operational coverage signal, not proof of
// dangerous behavior.
func (a *APIServer) recordParserUncertaintyMetricV8(
	ctx context.Context,
	connectorName string,
	count int64,
) {
	if a == nil || ctx == nil || count <= 0 {
		return
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return
	}
	recordParserUncertaintyMetricV8ForRuntime(
		ctx,
		runtime,
		connectorName,
		inspectMetricsV8Producer,
		count,
	)
}

func recordParserUncertaintyMetricV8ForRuntime(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	connectorName string,
	producer string,
	count int64,
) {
	if ctx == nil || runtime == nil || count <= 0 {
		return
	}
	connectorName = hookDecisionMetricConnector(connectorName)
	meta := hookDecisionMetricMeta(ctx, connectorName)
	meta.Source = connectorName
	item := newHookV8MetricBatchItemForProducer(
		ctx,
		time.Now().UTC(),
		meta,
		producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawGuardrailEvaluations),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawGuardrailEvaluations(
				observability.MetricDefenseClawGuardrailEvaluationsInput{
					Envelope:                            envelope,
					Value:                               count,
					DefenseClawGuardrailEffectiveAction: observability.Present(guardrailActionAllow),
					DefenseClawConnectorSource:          observability.Present(connectorName),
					DefenseClawMetricGuardrailScanner:   observability.Present(trustedParserUncertaintyMetricScanner),
				},
			)
		},
	)
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

func (a *APIServer) recordSecurityAlertMetricV8(
	ctx context.Context,
	connectorName string,
	severityValue string,
	alertType string,
	alertSource string,
) {
	if a == nil || ctx == nil {
		return
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return
	}
	severity := observability.NormalizeSeverity(severityValue)
	if !severity.Valid || !severity.Present {
		return
	}
	connectorName = hookDecisionMetricConnector(connectorName)
	alertType = telemetry.NormalizeMetricTextLabel(alertType)
	alertSource = telemetry.NormalizeMetricTextLabel(alertSource)
	if alertType == "unknown" || alertSource == "unknown" {
		return
	}
	meta := hookDecisionMetricMeta(ctx, connectorName)
	meta.Source = connectorName
	item := newHookV8MetricBatchItemForProducer(
		ctx, time.Now().UTC(), meta, inspectMetricsV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAlertCount),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawAlertCount(observability.MetricDefenseClawAlertCountInput{
				Envelope: envelope, Value: 1,
				DefenseClawMetricAlertSeverity: observability.Present(string(severity.Severity)),
				DefenseClawMetricAlertSource:   observability.Present(alertSource),
				DefenseClawMetricAlertType:     observability.Present(alertType),
				DefenseClawConnectorSource:     observability.Present(connectorName),
			})
		},
	)
	_, _ = runtime.RecordGeneratedMetricBatch(
		ctx, []observabilityruntime.GeneratedMetricBatchItem{item},
	)
}

func normalizeInspectMetricAction(action string) string {
	if strings.TrimSpace(action) == "" {
		return "unknown"
	}
	return normalizeHookActionLabel(action)
}
