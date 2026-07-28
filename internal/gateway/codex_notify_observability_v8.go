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

const codexNotifyV8Producer = "gateway.codex_notify"

func recordCodexNotifyV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	kind string,
	status string,
	result string,
	turnID string,
) {
	if ctx == nil || runtime == nil {
		return
	}
	kind = strings.TrimSpace(kind)
	if kind == "" {
		kind = "unknown"
	}
	result = strings.TrimSpace(result)
	if result == "" {
		result = "ok"
	}
	observedAt := time.Now().UTC()
	metric := func(
		family string,
		build hookV8MetricRecordBuilder,
	) observabilityruntime.GeneratedMetricBatchItem {
		return newGatewayGeneratedMetricItem(
			ctx, observedAt, observability.SourceConnector, "codex", codexNotifyV8Producer,
			observability.EventName(family),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				envelope.Correlation.SessionID = firstNonEmpty(envelope.Correlation.SessionID, SessionIDFromContext(ctx))
				if hookModelV8Identifier(turnID) {
					envelope.Correlation.TurnID = turnID
				}
				return build(builder, envelope)
			},
		)
	}
	items := []observabilityruntime.GeneratedMetricBatchItem{
		metric(observability.TelemetryInstrumentDefenseClawCodexNotify,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawCodexNotify(observability.MetricDefenseClawCodexNotifyInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricType:   hookV8OptionalText(kind, 256),
					DefenseClawMetricStatus: hookV8OptionalText(status, 256),
					DefenseClawMetricResult: hookV8OptionalText(result, 256),
				})
			}),
	}
	if result == "malformed" {
		items = append(items, metric(observability.TelemetryInstrumentDefenseClawCodexNotifyMalformed,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawCodexNotifyMalformed(observability.MetricDefenseClawCodexNotifyMalformedInput{
					Envelope: envelope, Value: 1, DefenseClawMetricType: hookV8OptionalText(kind, 256),
				})
			}))
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}
