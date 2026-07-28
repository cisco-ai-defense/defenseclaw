// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const eventRouterGuardrailV8Producer = "gateway.event_router.guardrail"

type eventRouterGuardrailMetricObservation struct {
	meta        llmEventMeta
	tool        string
	action      string
	severity    string
	alertType   string
	alertSource string
	observedAt  time.Time
}

// recordEventRouterGuardrailMetricsV8 preserves the local-observability
// guardrail and runtime-alert series through generated v8 metric families.
// It deliberately accepts source-backed facts only: an inspect evaluation is
// emitted when action is present, while an alert is emitted only when the
// caller observed a concrete security alert.
func (r *EventRouter) recordEventRouterGuardrailMetricsV8(
	ctx context.Context,
	observation eventRouterGuardrailMetricObservation,
) {
	if r == nil || ctx == nil {
		return
	}
	emitter, _, authoritative := r.observabilityV8CapabilitiesSnapshot()
	runtime, ok := emitter.(hookLifecycleMetricV8Runtime)
	if !authoritative || !ok || runtime == nil {
		return
	}
	observation.action = strings.TrimSpace(observation.action)
	observation.tool = strings.TrimSpace(observation.tool)
	observation.alertType = strings.TrimSpace(observation.alertType)
	observation.alertSource = strings.TrimSpace(observation.alertSource)
	if observation.action == "" && observation.alertType == "" {
		return
	}
	if observation.observedAt.IsZero() {
		observation.observedAt = time.Now().UTC()
	} else {
		observation.observedAt = observation.observedAt.UTC()
	}
	normalized := observability.NormalizeSeverity(observation.severity)
	if !normalized.Present || !normalized.Valid {
		return
	}
	severity := string(normalized.Severity)
	observation.meta.Source = eventRouterToolConnector
	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 2)
	if observation.action != "" {
		items = append(items, newHookV8MetricBatchItemForProducer(
			ctx, observation.observedAt, observation.meta, eventRouterGuardrailV8Producer,
			observability.EventName(observability.TelemetryInstrumentDefenseClawInspectEvaluations),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawInspectEvaluations(
					observability.MetricDefenseClawInspectEvaluationsInput{
						Envelope: envelope, Value: 1,
						DefenseClawMetricAction:     observability.Present(observation.action),
						DefenseClawConnectorSource:  observability.Present(eventRouterToolConnector),
						DefenseClawSecuritySeverity: observability.Present(severity),
						DefenseClawMetricTool:       hookModelV8OptionalText(observation.tool),
					},
				)
			},
		))
	}
	if observation.alertType != "" && observation.alertSource != "" {
		items = append(items, newHookV8MetricBatchItemForProducer(
			ctx, observation.observedAt, observation.meta, eventRouterGuardrailV8Producer,
			observability.EventName(observability.TelemetryInstrumentDefenseClawAlertCount),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawAlertCount(observability.MetricDefenseClawAlertCountInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricAlertSeverity: observability.Present(severity),
					DefenseClawMetricAlertSource:   observability.Present(observation.alertSource),
					DefenseClawMetricAlertType:     observability.Present(observation.alertType),
					DefenseClawConnectorSource:     observability.Present(eventRouterToolConnector),
				})
			},
		))
	}
	if len(items) > 0 {
		_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
	}
}
