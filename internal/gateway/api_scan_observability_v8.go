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

const apiScanV8Producer = "gateway.api.scan"

func (a *APIServer) recordAPIScanErrorV8(
	ctx context.Context,
	scannerName string,
	targetType string,
	errorType string,
) {
	if a == nil || ctx == nil {
		return
	}
	runtime, _ := a.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	if runtime == nil {
		return
	}
	recordScanErrorV8(ctx, runtime, apiScanV8Producer, scannerName, targetType, errorType)
}

func recordScanErrorV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	producer string,
	scannerName string,
	targetType string,
	errorType string,
) {
	if ctx == nil || runtime == nil {
		return
	}
	connector := strings.TrimSpace(audit.EnvelopeFromContext(ctx).Connector)
	if connector != "" && !observability.IsStableToken(connector) {
		connector = ""
	}
	item := newGatewayGeneratedMetricItem(
		ctx, time.Now().UTC(), observability.SourceScanner, connector, producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawScanErrors),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawScanErrors(observability.MetricDefenseClawScanErrorsInput{
				Envelope: envelope, Value: 1,
				DefenseClawScanScanner:      observability.Present(scannerName),
				DefenseClawMetricTargetType: observability.Present(targetType),
				DefenseClawMetricErrorType:  observability.Present(errorType),
			})
		},
	)
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}
