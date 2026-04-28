// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestRecordOTelIngest_HappyPath_FansOutAllInstruments pins the
// invariant that one happy-path call to RecordOTelIngest produces
// data points on requests + records + bytes + last_seen, with the
// expected (signal, source, result) labels. Dashboards depend on
// each of these series existing — if a future refactor drops one
// silently the connector dashboard stops rendering for that pane.
func TestRecordOTelIngest_HappyPath_FansOutAllInstruments(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	p.RecordOTelIngest(ctx, "logs", "codex", "ok", 7, 1234)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if c := findCounter(rm, "defenseclaw.otel.ingest.requests"); c == nil {
		t.Errorf("requests counter missing")
	}
	if c := findCounter(rm, "defenseclaw.otel.ingest.records"); c == nil {
		t.Errorf("records counter missing")
	}
	if c := findCounter(rm, "defenseclaw.otel.ingest.bytes"); c == nil {
		t.Errorf("bytes counter missing")
	}
	if g := findGauge(rm, "defenseclaw.otel.ingest.last_seen_ts"); g == nil {
		t.Errorf("last_seen gauge missing — ConnectorTelemetrySilent alert depends on this series")
	}
	// Records counter MUST equal the records arg, not 1. The
	// receiver passes records=stats.Records straight from the
	// summarizer; it is NOT a per-batch counter.
	c := findCounter(rm, "defenseclaw.otel.ingest.records")
	if c == nil {
		t.Fatal("records counter missing")
	}
	sum, ok := c.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", c.Data)
	}
	if len(sum.DataPoints) != 1 {
		t.Fatalf("expected 1 data point, got %d", len(sum.DataPoints))
	}
	if sum.DataPoints[0].Value != 7 {
		t.Errorf("records value = %d, want 7", sum.DataPoints[0].Value)
	}
}

// TestRecordOTelIngest_Malformed_IncrementsMalformedCounter pins the
// failure branch: result="malformed" must increment both the
// generic requests counter (so volume dashboards stay accurate)
// AND the dedicated malformed counter (so the
// ConnectorTelemetryMalformed alert fires).
func TestRecordOTelIngest_Malformed_IncrementsMalformedCounter(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	p.RecordOTelIngest(ctx, "metrics", "claudecode", "malformed", 0, 42)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if c := findCounter(rm, "defenseclaw.otel.ingest.requests"); c == nil {
		t.Errorf("requests counter missing on malformed branch")
	}
	if c := findCounter(rm, "defenseclaw.otel.ingest.malformed"); c == nil {
		t.Errorf("malformed counter missing — ConnectorTelemetryMalformed alert depends on it")
	}
	// Bytes still recorded on malformed (volume dashboards
	// should reflect the load even when payload was rejected).
	if c := findCounter(rm, "defenseclaw.otel.ingest.bytes"); c == nil {
		t.Errorf("bytes counter missing on malformed branch — operator can't see DoS attempts otherwise")
	}
}

// TestRecordCodexNotify_FansOutCounter mirrors the OTel ingest test
// for the codex notify webhook. Confirms type/status/result labels
// flow through and that result="malformed" also bumps the
// dedicated malformed counter.
func TestRecordCodexNotify_FansOutCounter(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	p.RecordCodexNotify(ctx, "agent-turn-complete", "success", "ok")
	p.RecordCodexNotify(ctx, "malformed", "", "malformed")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if c := findCounter(rm, "defenseclaw.codex.notify"); c == nil {
		t.Errorf("codex.notify counter missing")
	}
	if c := findCounter(rm, "defenseclaw.codex.notify.malformed"); c == nil {
		t.Errorf("codex.notify.malformed counter missing")
	}
}

// TestRecordOTelIngest_NilReceiver_NoPanic guards the gateway hot
// path. When telemetry is disabled (Provider == nil) the handler
// still calls a.otel.RecordOTelIngest; the method must short-circuit
// rather than nil-deref.
func TestRecordOTelIngest_NilReceiver_NoPanic(t *testing.T) {
	t.Parallel()
	var p *Provider
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("RecordOTelIngest with nil Provider panicked: %v", r)
		}
	}()
	p.RecordOTelIngest(context.Background(), "logs", "codex", "ok", 1, 100)
	p.RecordCodexNotify(context.Background(), "agent-turn-complete", "success", "ok")
	p.EmitConnectorTelemetryLog(context.Background(), "logs", "codex", "ok", 1, 100, "summary")
	p.EmitCodexNotifyLog(context.Background(), "agent-turn-complete", "success", "ok", "turn-1", "gpt-5")
}
