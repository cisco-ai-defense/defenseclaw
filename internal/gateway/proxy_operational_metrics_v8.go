// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const proxyOperationalV8Producer = "gateway.proxy.operational"

func (p *GuardrailProxy) proxyOperationalV8Runtime() hookLifecycleMetricV8Runtime {
	if p == nil {
		return nil
	}
	runtime, _ := p.observabilityV8TraceRuntime().(hookLifecycleMetricV8Runtime)
	return runtime
}

func (trace *proxyV8RequestTrace) metricRuntime() hookLifecycleMetricV8Runtime {
	if trace == nil {
		return nil
	}
	if trace.agent != nil {
		return trace.agent
	}
	runtime, _ := trace.runtime.(hookLifecycleMetricV8Runtime)
	return runtime
}

func (p *GuardrailProxy) recordProxyRateLimitV8(ctx context.Context, route string) {
	runtime := p.proxyOperationalV8Runtime()
	if ctx == nil || runtime == nil {
		return
	}
	meta := hookDecisionMetricMeta(ctx, hookDecisionMetricConnector(p.connectorName()))
	item := proxyOperationalV8MetricItem(
		ctx, time.Now().UTC(), meta,
		observability.TelemetryInstrumentDefenseClawHTTPRateLimitBreaches,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawHTTPRateLimitBreaches(
				observability.MetricDefenseClawHTTPRateLimitBreachesInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricClientKind: observability.Present("global"),
					HTTPRoute:                   observability.Present(proxyOperationalRoute(route)),
				},
			)
		},
	)
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

func (p *GuardrailProxy) recordProxyForwardedHeadersV8(
	ctx context.Context,
	path string,
	result string,
	count int64,
) {
	runtime := p.proxyOperationalV8Runtime()
	if ctx == nil || runtime == nil || count <= 0 {
		return
	}
	path = strings.TrimSpace(path)
	if path != "chat-completions" && path != "passthrough" {
		path = "passthrough"
	}
	switch result {
	case "ok", "rejected_invalid", "rejected_overflow":
	default:
		result = "rejected_invalid"
	}
	meta := hookDecisionMetricMeta(ctx, hookDecisionMetricConnector(p.connectorName()))
	item := proxyOperationalV8MetricItem(
		ctx, time.Now().UTC(), meta,
		observability.TelemetryInstrumentDefenseClawGatewayForwardedHeaders,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawGatewayForwardedHeaders(
				observability.MetricDefenseClawGatewayForwardedHeadersInput{
					Envelope: envelope, Value: count,
					DefenseClawMetricPath:   observability.Present(path),
					DefenseClawMetricResult: observability.Present(result),
				},
			)
		},
	)
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

func (p *GuardrailProxy) recordProxyStreamV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	route string,
	transition string,
	outcome observability.Outcome,
	duration time.Duration,
	bytesSent int64,
) {
	if p == nil || ctx == nil || runtime == nil {
		return
	}
	if transition != "open" && transition != "close" {
		return
	}
	route = proxyOperationalRoute(route)
	meta := hookDecisionMetricMeta(ctx, hookDecisionMetricConnector(p.connectorName()))
	observedAt := time.Now().UTC()
	items := []observabilityruntime.GeneratedMetricBatchItem{
		proxyOperationalV8MetricItem(
			ctx, observedAt, meta, observability.TelemetryInstrumentDefenseClawStreamLifecycle,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawStreamLifecycle(observability.MetricDefenseClawStreamLifecycleInput{
					Envelope: envelope, Value: 1,
					HTTPRoute:                   observability.Present(route),
					DefenseClawOutcome:          observability.Present(string(outcome)),
					DefenseClawMetricTransition: observability.Present(transition),
				})
			},
		),
	}
	if transition == "close" {
		durationMs := float64(duration) / float64(time.Millisecond)
		if duration >= 0 && !math.IsNaN(durationMs) && !math.IsInf(durationMs, 0) {
			items = append(items, proxyOperationalV8MetricItem(
				ctx, observedAt, meta, observability.TelemetryInstrumentDefenseClawStreamDurationMs,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawStreamDurationMs(observability.MetricDefenseClawStreamDurationMsInput{
						Envelope: envelope, Value: durationMs,
						HTTPRoute:          observability.Present(route),
						DefenseClawOutcome: observability.Present(string(outcome)),
					})
				},
			))
		}
		if bytesSent >= 0 {
			items = append(items, proxyOperationalV8MetricItem(
				ctx, observedAt, meta, observability.TelemetryInstrumentDefenseClawStreamBytesSent,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawStreamBytesSent(observability.MetricDefenseClawStreamBytesSentInput{
						Envelope: envelope, Value: bytesSent,
						HTTPRoute:          observability.Present(route),
						DefenseClawOutcome: observability.Present(string(outcome)),
					})
				},
			))
		}
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

func proxyOperationalV8MetricItem(
	ctx context.Context,
	observedAt time.Time,
	meta llmEventMeta,
	family string,
	build hookV8MetricRecordBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	return newHookV8MetricBatchItemForProducer(
		ctx, observedAt, meta, proxyOperationalV8Producer, observability.EventName(family), build,
	)
}

func proxyOperationalRoute(route string) string {
	if strings.TrimSpace(route) == "/v1/chat/completions" {
		return "/v1/chat/completions"
	}
	return "passthrough"
}
