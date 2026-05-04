// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestRefreshMsg_RecordsTUIRefreshHistogram(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	prov, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

	refreshTestHook = func() { time.Sleep(100 * time.Millisecond) }
	defer func() { refreshTestHook = nil }()

	m := New(Deps{Version: "test", OTel: prov})
	next, _ := m.Update(refreshMsg{})
	_ = next.(Model)

	ctx := context.Background()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	h := findTestHistogram(rm, "defenseclaw.slo.tui.refresh")
	if h == nil {
		t.Fatal("histogram defenseclaw.slo.tui.refresh not found")
		return
	}
	hist, ok := h.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected histogram float64, got %T", h.Data)
	}
	if len(hist.DataPoints) == 0 {
		t.Fatal("no data points")
	}
	dp := hist.DataPoints[0]
	if dp.Count < 1 {
		t.Fatalf("count=%d", dp.Count)
	}
	if dp.Sum < 80 {
		t.Fatalf("sum=%f expected >= ~100ms work", dp.Sum)
	}
}

func findTestHistogram(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}
