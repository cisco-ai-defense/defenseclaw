// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"go.opentelemetry.io/otel/trace"
)

const webhookV8Producer = "gateway.webhook"

func (d *WebhookDispatcher) BindObservabilityV8(runtime hookLifecycleMetricV8Runtime) {
	if d == nil {
		return
	}
	d.observabilityV8Mu.Lock()
	d.observabilityV8 = runtime
	d.observabilityV8Mu.Unlock()
}

func (d *WebhookDispatcher) observabilityV8Snapshot() hookLifecycleMetricV8Runtime {
	if d == nil {
		return nil
	}
	d.observabilityV8Mu.RLock()
	defer d.observabilityV8Mu.RUnlock()
	return d.observabilityV8
}

func (d *WebhookDispatcher) recordCircuitTransitionV8(ctx context.Context, targetHash, state string) {
	d.recordWebhookMetricBatchV8(ctx, []observabilityruntime.GeneratedMetricBatchItem{
		d.webhookMetricItemV8(ctx, observability.TelemetryInstrumentDefenseClawWebhookCircuitBreaker,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawWebhookCircuitBreaker(observability.MetricDefenseClawWebhookCircuitBreakerInput{
					Envelope: envelope, Value: 1,
					DefenseClawWebhookCircuitState:     webhookV8OptionalLabel(state),
					DefenseClawMetricWebhookTargetHash: webhookV8OptionalTargetHash(targetHash),
				})
			}),
	})
}

func (d *WebhookDispatcher) recordDeliveryV8(
	ctx context.Context,
	kind, targetHash, outcome string,
	status int,
	latencyMS float64,
	cooldownSuppressed bool,
) {
	_ = d.recordDeliveryConfirmedV8(ctx, kind, targetHash, outcome, status, latencyMS, cooldownSuppressed)
}

func (d *WebhookDispatcher) recordDeliveryConfirmedV8(
	ctx context.Context,
	kind, targetHash, outcome string,
	status int,
	latencyMS float64,
	cooldownSuppressed bool,
) error {
	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 4)
	appendMetric := func(family string, build hookV8MetricRecordBuilder) {
		items = append(items, d.webhookMetricItemV8(ctx, family, build))
	}
	if cooldownSuppressed {
		appendMetric(observability.TelemetryInstrumentDefenseClawWebhookCooldownSuppressed,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawWebhookCooldownSuppressed(observability.MetricDefenseClawWebhookCooldownSuppressedInput{
					Envelope: envelope, Value: 1, DefenseClawMetricWebhookKind: webhookV8OptionalKind(kind),
				})
			})
	}
	appendMetric(observability.TelemetryInstrumentDefenseClawWebhookDispatches,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawWebhookDispatches(observability.MetricDefenseClawWebhookDispatchesInput{
				Envelope: envelope, Value: 1, DefenseClawOutcome: webhookV8OptionalOutcome(outcome),
				DefenseClawMetricWebhookKind: webhookV8OptionalKind(kind),
			})
		})
	if outcome != "delivered" {
		appendMetric(observability.TelemetryInstrumentDefenseClawWebhookFailures,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawWebhookFailures(observability.MetricDefenseClawWebhookFailuresInput{
					Envelope: envelope, Value: 1, DefenseClawOutcome: webhookV8OptionalOutcome(outcome),
					DefenseClawMetricWebhookKind: webhookV8OptionalKind(kind),
				})
			})
	}
	appendMetric(observability.TelemetryInstrumentDefenseClawWebhookLatency,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawWebhookLatency(observability.MetricDefenseClawWebhookLatencyInput{
				Envelope: envelope, Value: latencyMS, HTTPResponseStatusCode: observability.Present(int64(status)),
				DefenseClawMetricWebhookKind:       webhookV8OptionalKind(kind),
				DefenseClawMetricWebhookTargetHash: webhookV8OptionalTargetHash(targetHash),
			})
		})
	return d.recordWebhookMetricBatchV8(ctx, items)
}

func (d *WebhookDispatcher) webhookMetricItemV8(
	ctx context.Context,
	family string,
	build hookV8MetricRecordBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	connector := strings.ToLower(strings.TrimSpace(audit.EnvelopeFromContext(ctx).Connector))
	if !observability.IsStableToken(connector) {
		connector = ""
	}
	return newGatewayGeneratedMetricItem(
		ctx, time.Now().UTC(), observability.SourceGateway, connector, webhookV8Producer,
		observability.EventName(family), build,
	)
}

func (d *WebhookDispatcher) recordWebhookMetricBatchV8(
	ctx context.Context,
	items []observabilityruntime.GeneratedMetricBatchItem,
) error {
	runtime := d.observabilityV8Snapshot()
	if runtime == nil || len(items) == 0 {
		return errors.New("gateway: canonical webhook metric runtime unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	metricCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	_, err := runtime.RecordGeneratedMetricBatch(metricCtx, items)
	return err
}

func webhookMetricContext(event audit.Event) context.Context {
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		RunID: event.RunID, TraceID: event.TraceID, RequestID: event.RequestID,
		SessionID: event.SessionID, TurnID: event.TurnID, AgentID: event.AgentID,
		AgentName: event.AgentName, AgentInstanceID: event.AgentInstanceID,
		SidecarInstanceID: event.SidecarInstanceID, PolicyID: event.PolicyID,
		DestinationApp: event.DestinationApp, ToolName: event.ToolName, ToolID: event.ToolID,
		Connector: event.Connector,
	})
	traceID, traceErr := trace.TraceIDFromHex(event.TraceID)
	spanID, spanErr := trace.SpanIDFromHex(event.SpanID)
	if traceErr == nil && spanErr == nil && traceID.IsValid() && spanID.IsValid() {
		ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: traceID,
			SpanID:  spanID,
		}))
	}
	return ctx
}

func webhookV8OptionalKind(value string) observability.Optional[string] {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = "generic"
	}
	return webhookV8OptionalLabel(value)
}

func webhookV8OptionalOutcome(value string) observability.Optional[string] {
	canonical := map[string]string{
		"delivered":           string(observability.OutcomeCompleted),
		"failed":              string(observability.OutcomeFailed),
		"cooldown_suppressed": string(observability.OutcomeSkipped),
		"circuit_open":        string(observability.OutcomeBlocked),
	}[strings.ToLower(strings.TrimSpace(value))]
	if canonical == "" {
		canonical = string(observability.OutcomeFailed)
	}
	return observability.Present(canonical)
}

func webhookV8OptionalLabel(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if !observability.IsStableToken(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func webhookV8OptionalTargetHash(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	digest := strings.TrimPrefix(value, "hmac-sha256:")
	if digest == value || len(digest) != sha256.Size*2 {
		return observability.Absent[string]()
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}
