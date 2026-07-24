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

const judgeStoreV8Producer = "gateway.judge_store"

func (j *JudgeStore) bindObservabilityV8(runtime hookLifecycleMetricV8Runtime) {
	if j == nil {
		return
	}
	j.observabilityV8Mu.Lock()
	j.observabilityV8 = runtime
	j.observabilityV8Mu.Unlock()
}

func (j *JudgeStore) observabilityV8Snapshot() hookLifecycleMetricV8Runtime {
	if j == nil {
		return nil
	}
	j.observabilityV8Mu.RLock()
	defer j.observabilityV8Mu.RUnlock()
	return j.observabilityV8
}

func (j *JudgeStore) recordPersistDropV8(ctx context.Context, reason string) {
	j.recordPersistMetricV8(
		ctx, observability.EventName(observability.TelemetryInstrumentDefenseClawJudgePersistDrops),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawJudgePersistDrops(observability.MetricDefenseClawJudgePersistDropsInput{
				Envelope: envelope, Value: 1, DefenseClawMetricReason: hookV8OptionalText(reason, 256),
			})
		},
	)
}

func (j *JudgeStore) recordPersistQueueDepthV8(ctx context.Context, depth int64) {
	j.recordPersistMetricV8(
		ctx, observability.EventName(observability.TelemetryInstrumentDefenseClawJudgePersistQueueDepth),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawJudgePersistQueueDepth(observability.MetricDefenseClawJudgePersistQueueDepthInput{
				Envelope: envelope, Value: depth,
			})
		},
	)
}

func (j *JudgeStore) recordPersistBatchSizeV8(ctx context.Context, size int64) {
	j.recordPersistMetricV8(
		ctx, observability.EventName(observability.TelemetryInstrumentDefenseClawJudgePersistBatchSize),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawJudgePersistBatchSize(observability.MetricDefenseClawJudgePersistBatchSizeInput{
				Envelope: envelope, Value: size,
			})
		},
	)
}

func (j *JudgeStore) recordPersistMetricV8(
	ctx context.Context,
	family observability.EventName,
	build hookV8MetricRecordBuilder,
) {
	runtime := j.observabilityV8Snapshot()
	if runtime == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Shutdown and queue-overflow accounting must remain observable after the
	// originating request is canceled. WithoutCancel retains every correlation
	// value while preventing a stale cancellation from suppressing the metric.
	metricCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	connector := strings.ToLower(strings.TrimSpace(audit.EnvelopeFromContext(ctx).Connector))
	if !observability.IsStableToken(connector) {
		connector = ""
	}
	item := newGatewayGeneratedMetricItem(
		ctx, time.Now().UTC(), observability.SourceGateway, connector, judgeStoreV8Producer,
		family, build,
	)
	_, _ = runtime.RecordGeneratedMetricBatch(metricCtx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

func (j *JudgeStore) recordPersistDropsV8(jobs []judgePersistJob, reason string) {
	for _, job := range jobs {
		j.recordPersistDropV8(job.ctx, reason)
	}
}
