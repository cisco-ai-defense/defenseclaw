// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const judgeCacheV8Producer = "gateway.judge_cache"

func recordJudgeCacheMetricV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	hit bool,
	scanner, verdict, ttlBucket string,
) {
	if runtime == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	family := observability.TelemetryInstrumentDefenseClawGuardrailCacheMisses
	if hit {
		family = observability.TelemetryInstrumentDefenseClawGuardrailCacheHits
	}
	connector := strings.ToLower(strings.TrimSpace(audit.EnvelopeFromContext(ctx).Connector))
	if !observability.IsStableToken(connector) {
		connector = ""
	}
	build := func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		if hit {
			return builder.BuildMetricDefenseClawGuardrailCacheHits(observability.MetricDefenseClawGuardrailCacheHitsInput{
				Envelope: envelope, Value: 1,
				DefenseClawMetricCache:     observability.Present("verdict"),
				DefenseClawScanScanner:     hookV8OptionalIdentifier(scanner),
				DefenseClawMetricTtlBucket: hookV8OptionalText(ttlBucket, 256),
				DefenseClawMetricVerdict:   hookV8OptionalText(verdict, 256),
			})
		}
		return builder.BuildMetricDefenseClawGuardrailCacheMisses(observability.MetricDefenseClawGuardrailCacheMissesInput{
			Envelope: envelope, Value: 1,
			DefenseClawMetricCache:     observability.Present("verdict"),
			DefenseClawScanScanner:     hookV8OptionalIdentifier(scanner),
			DefenseClawMetricTtlBucket: hookV8OptionalText(ttlBucket, 256),
			DefenseClawMetricVerdict:   hookV8OptionalText(verdict, 256),
		})
	}
	item := newGatewayGeneratedMetricItem(
		ctx, time.Now().UTC(), observability.SourceGateway, connector, judgeCacheV8Producer,
		observability.EventName(family), build,
	)
	emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	_, _ = runtime.RecordGeneratedMetricBatch(emitCtx, []observabilityruntime.GeneratedMetricBatchItem{item})
}
