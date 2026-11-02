// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// recordMCPToolInventoryMetric emits only fixed labels. Scanner errors, tool
// names, server URLs, and hook arguments never become metric dimensions.
func recordMCPToolInventoryMetric(ctx context.Context, runtime hookLifecycleMetricV8Runtime, stage, outcome, reason string) {
	if ctx == nil || runtime == nil {
		return
	}
	switch stage {
	case "list", "export":
	default:
		return
	}
	switch outcome {
	case "success", "submitted", "empty", "partial", "error":
	default:
		return
	}
	switch reason {
	case "none", "scan_failed", "incomplete", "publish_error":
	default:
		return
	}
	item := newGatewayGeneratedMetricItem(ctx, time.Now().UTC(), observability.SourceSystem, "",
		"gateway.inventory.mcp_tools", observability.EventName(observability.TelemetryInstrumentDefenseClawInventoryMcpToolEvents),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawInventoryMcpToolEvents(observability.MetricDefenseClawInventoryMcpToolEventsInput{
				Envelope: envelope, Value: 1,
				DefenseClawInventoryMcpToolStage:   stage,
				DefenseClawInventoryMcpToolOutcome: outcome,
				DefenseClawInventoryMcpToolReason:  reason,
			})
		})
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}
