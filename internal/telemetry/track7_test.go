// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"math"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestRecordRuntimeMetrics_Gauges(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordRuntimeMetrics(ctx, RuntimeMetrics{
		Goroutines:     42,
		HeapAllocBytes: 1024,
		HeapObjects:    99,
		GCPauseP99Ns:   5000,
		FDsOpen:        7,
		UptimeSeconds:  123.4,
	})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	assertGauge(t, rm, "defenseclaw.runtime.goroutines", 42, "{goroutine}")
	assertGauge(t, rm, "defenseclaw.runtime.heap.alloc", 1024, "By")
	assertGauge(t, rm, "defenseclaw.runtime.heap.objects", 99, "{object}")
	assertGauge(t, rm, "defenseclaw.runtime.fd.in_use", 7, "{fd}")
	assertFloatGauge(t, rm, "defenseclaw.process.uptime_seconds", 123.4, "s")
}

func TestGcPauseP99Ns_SyntheticMemStats(t *testing.T) {
	t.Parallel()
	var ms runtime.MemStats
	for i := 0; i < 100; i++ {
		ms.PauseNs[i] = uint64(i+1) * 1000
	}
	ms.NumGC = 100
	p99 := gcPauseP99Ns(&ms)
	if p99 <= 0 {
		t.Fatalf("expected positive p99, got %d", p99)
	}
}

func TestRecordSQLiteHealth_CheckpointHistogram(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordSQLiteHealth(ctx, SQLiteHealthMetrics{
		DBSizeBytes:   4096,
		WALSizeBytes:  512,
		PageCount:     10,
		FreelistCount: 1,
		CheckpointMs:  3.5,
	})
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	h := findHistogram(rm, "defenseclaw.sqlite.checkpoint.duration")
	if h == nil {
		t.Fatal("checkpoint histogram missing")
		return
	}
	hf, ok := h.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("want float64 histogram, got %T", h.Data)
	}
	if len(hf.DataPoints) != 1 || hf.DataPoints[0].Count != 1 {
		t.Fatalf("expected 1 sample, got %+v", hf.DataPoints)
	}
}

func TestQueueDepthAndDrops(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const cap = 100
	p.RecordQueueDepth(ctx, "test_queue", 90, cap)
	p.RecordQueueDropped(ctx, "test_queue", "full")
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	g := findGauge(rm, "defenseclaw.queue.depth")
	if g == nil {
		t.Fatal("queue depth gauge missing")
		return
	}
	gd, ok := g.Data.(metricdata.Gauge[int64])
	if !ok {
		t.Fatalf("expected Gauge[int64], got %T", g.Data)
	}
	if len(gd.DataPoints) != 1 || gd.DataPoints[0].Value != 90 {
		t.Fatalf("depth = %+v", gd.DataPoints)
	}
	c := findCounter(rm, "defenseclaw.queue.drops")
	if c == nil {
		t.Fatal("queue drops counter missing")
		return
	}
}

func TestRecordPanic_CounterAndRecover(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	RecoverPanic(ctx, p, gatewaylog.SubsystemTelemetry, func() {
		panic("boom")
	})
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	c := findCounter(rm, "defenseclaw.panics.total")
	if c == nil {
		t.Fatal("panics counter missing")
		return
	}
}

func TestSLOHistogram_DistributionQuantiles(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 1000; i++ {
		ms := float64((i % 50) * 10)
		p.RecordBlockSLO(ctx, "skill", ms)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	h := findHistogram(rm, "defenseclaw.slo.block.latency")
	if h == nil {
		t.Fatal("slo block histogram missing")
		return
	}
	hf := h.Data.(metricdata.Histogram[float64])
	if len(hf.DataPoints) == 0 {
		t.Fatal("no datapoints")
	}
	dp := hf.DataPoints[0]
	if dp.Count != 1000 {
		t.Fatalf("count = %d want 1000", dp.Count)
	}
	p50 := approximatePercentile(dp.Bounds, dp.BucketCounts, 0.50)
	p95 := approximatePercentile(dp.Bounds, dp.BucketCounts, 0.95)
	p99 := approximatePercentile(dp.Bounds, dp.BucketCounts, 0.99)
	if p50 <= 0 || p95 <= p50 || p99 < p95 {
		t.Fatalf("implausible quantiles p50=%v p95=%v p99=%v", p50, p95, p99)
	}
	// Bucket boundaries include 2000ms for block SLO dashboards.
	has2000 := false
	for _, b := range dp.Bounds {
		if math.Abs(b-2000) < 0.01 {
			has2000 = true
		}
	}
	if !has2000 {
		t.Fatalf("expected 2000ms bucket edge in %+v", dp.Bounds)
	}
}

func TestRecordSSELifecycle_OpenAndClose(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordSSELifecycle(ctx, "/v1/chat/completions", "open", "ok", 0, 0)
	p.RecordSSELifecycle(ctx, "/v1/chat/completions", "close", "ok", 1234, 4096)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	if c := findCounter(rm, "defenseclaw.stream.lifecycle"); c == nil {
		t.Fatal("stream lifecycle counter missing")
	}
	if h := findHistogram(rm, "defenseclaw.stream.duration_ms"); h == nil {
		t.Fatal("stream duration histogram missing")
	}
	if h := findHistogram(rm, "defenseclaw.stream.bytes_sent"); h == nil {
		t.Fatal("stream bytes histogram missing")
	}
}

func TestRecordRedactionApplied_EmitsCounter(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	p.RecordRedactionApplied(context.Background(), "guardrail.pii", "messages[].content")
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	if c := findCounter(rm, "defenseclaw.redaction.applied"); c == nil {
		t.Fatal("redaction counter missing")
	}
}

func TestEmitGatewayEvent_IncrementsEmittedCounter(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	p.EmitGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventLifecycle,
		Severity:  gatewaylog.SeverityInfo,
		Lifecycle: &gatewaylog.LifecyclePayload{Subsystem: "gateway", Transition: "start"},
	})
	p.EmitGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error:     &gatewaylog.ErrorPayload{Subsystem: "auth", Code: "AUTH_INVALID_TOKEN"},
	})
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	c := findCounter(rm, "defenseclaw.gateway.events.emitted")
	if c == nil {
		t.Fatal("defenseclaw.gateway.events.emitted counter missing — fanout not wired")
		return
	}
	sum, ok := c.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("unexpected data type %T", c.Data)
	}
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	if total != 2 {
		t.Fatalf("emitted total=%d want 2", total)
	}
}

func TestRecordConfigLoadError_EmitsMetric(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordConfigLoadError(ctx, "unmarshal")
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	c := findCounter(rm, "defenseclaw.config.load.errors")
	if c == nil {
		t.Fatal("config load errors counter missing")
		return
	}
}

func TestRecordExporterHealth_LastExport(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordExporterHealth(ctx, "otlp_metrics", ExporterHealthSuccess)
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	g := findGauge(rm, "defenseclaw.telemetry.exporter.last_export_ts")
	if g == nil {
		t.Fatal("last_export_ts gauge missing")
		return
	}
}

func TestRecordSQLiteBusy_Counter(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	setGlobalTelemetryProvider(p)
	t.Cleanup(func() { setGlobalTelemetryProvider(nil) })

	p.RecordSQLiteBusy(ctx, "unit_test")
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	c := findCounter(rm, "defenseclaw.sqlite.busy_retries")
	if c == nil {
		t.Fatal("sqlite busy counter missing")
		return
	}
}

// Helpers using provider_test patterns

func assertGauge(t *testing.T, rm metricdata.ResourceMetrics, name string, want int64, unit string) {
	t.Helper()
	m := findGauge(rm, name)
	if m == nil {
		t.Fatalf("metric %s not found", name)
		return
	}
	if unit != "" && m.Unit != unit {
		t.Fatalf("%s: expected unit %q, got %q", name, unit, m.Unit)
	}
	gd, ok := m.Data.(metricdata.Gauge[int64])
	if !ok {
		t.Fatalf("%s: expected Gauge[int64], got %T", name, m.Data)
	}
	if len(gd.DataPoints) < 1 {
		t.Fatalf("%s: no data points", name)
	}
	if gd.DataPoints[0].Value != want {
		t.Fatalf("%s: got %d want %d", name, gd.DataPoints[0].Value, want)
	}
}

func assertFloatGauge(t *testing.T, rm metricdata.ResourceMetrics, name string, want float64, unit string) {
	t.Helper()
	m := findGauge(rm, name)
	if m == nil {
		t.Fatalf("metric %s not found", name)
		return
	}
	gd, ok := m.Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("%s: expected Gauge[float64], got %T", name, m.Data)
	}
	if len(gd.DataPoints) < 1 {
		t.Fatalf("%s: no data points", name)
	}
	if math.Abs(gd.DataPoints[0].Value-want) > 0.01 {
		t.Fatalf("%s: got %v want %v", name, gd.DataPoints[0].Value, want)
	}
}

func findGauge(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func approximatePercentile(bounds []float64, counts []uint64, p float64) float64 {
	var total uint64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := uint64(float64(total) * p)
	var cum uint64
	for i, c := range counts {
		cum += c
		upper := math.Inf(1)
		if i < len(bounds) {
			upper = bounds[i]
		}
		if cum >= target {
			return upper
		}
	}
	if len(bounds) > 0 {
		return bounds[len(bounds)-1]
	}
	return 0
}
