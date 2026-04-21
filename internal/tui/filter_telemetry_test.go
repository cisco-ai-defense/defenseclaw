// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestEmitTUIFilter_TraceAndMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	p, err := telemetry.NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Shutdown(context.Background()) }()

	ctx := context.Background()
	p.EmitTUIFilterTrace(ctx, "logs", FilterTypeSeverity, "HIGH", "MEDIUM")
	p.RecordTUIFilterApplied(ctx, "logs", FilterTypeSeverity)
	p.EmitTUIFilterTrace(ctx, "logs", FilterTypeEventType, "verdict", "judge")
	p.RecordTUIFilterApplied(ctx, "logs", FilterTypeEventType)
	p.EmitTUIFilterTrace(ctx, "alerts", FilterTypeAgentID, "", "agent-1")
	p.RecordTUIFilterApplied(ctx, "alerts", FilterTypeAgentID)

	spans := exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("spans=%d want 3", len(spans))
	}
	for _, s := range spans {
		if s.Name != "defenseclaw.tui.filter" {
			t.Errorf("span name=%q", s.Name)
		}
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	found := telemetryTestFindCounter(t, rm, "defenseclaw.tui.filter.applied")
	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected sum, got %T", found.Data)
	}
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	if total != 3 {
		t.Fatalf("filter counter total=%d want 3", total)
	}
}

// telemetryTestFindCounter is a minimal copy of telemetry.findCounter for the tui package.
func telemetryTestFindCounter(t *testing.T, rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	t.Fatalf("metric %q not found", name)
	return nil
}
