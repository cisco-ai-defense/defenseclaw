// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// multiMetricData returns resource metrics carrying exactly count metrics, so a
// test can tell batch accounting apart from record accounting.
func multiMetricData(count int) *metricdata.ResourceMetrics {
	metrics := make([]metricdata.Metrics, 0, count)
	for i := 0; i < count; i++ {
		metrics = append(metrics, metricdata.Metrics{
			Name: "defenseclaw.metric.circuit.accounting",
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{{Value: int64(i), Time: time.Unix(1, 0)}},
			},
		})
	}
	return &metricdata.ResourceMetrics{
		Resource: resource.NewSchemaless(),
		ScopeMetrics: []metricdata.ScopeMetrics{{
			Scope:   instrumentation.Scope{Name: "defenseclaw"},
			Metrics: metrics,
		}},
	}
}

func sizedMetricExporter(
	t *testing.T,
	inner *metricCircuitInner,
	at time.Time,
	metrics *metricdata.ResourceMetrics,
) *MetricExporter {
	t.Helper()
	exporter := newMetricCircuitTestExporter(t, inner, &dialOutcomeTracker{}, func() time.Time {
		return at
	})
	bound, ok := conservativeMetricBytes(metrics)
	if !ok {
		t.Fatal("accounting metric data has no conservative bound")
	}
	exporter.maxBytes = bound
	return exporter
}

// An open circuit reports success to the SDK on purpose, so its counters are
// the only evidence that data was discarded. A batch count alone cannot answer
// "how much did we lose", which is what this asserts.
func TestMetricOpenCircuitCountsSuppressedRecordsNotJustBatches(t *testing.T) {
	start := time.Date(2026, time.July, 30, 17, 0, 0, 0, time.UTC)
	inner := &metricCircuitInner{}
	exporter := sizedMetricExporter(t, inner, start, multiMetricData(7))

	// Open the circuit without any successful export first.
	if !exporter.circuit.RecordFailure(delivery.FailureClassAuthentication, start) {
		t.Fatal("authentication failure should open the circuit immediately")
	}

	if err := exporter.Export(t.Context(), multiMetricData(7)); err != nil {
		t.Fatalf("blocked export should be a silent no-op, got %v", err)
	}
	if err := exporter.Export(t.Context(), multiMetricData(3)); err != nil {
		t.Fatalf("second blocked export error=%v", err)
	}

	if inner.calls.Load() != 0 {
		t.Fatalf("open circuit reached the inner exporter %d times", inner.calls.Load())
	}
	counters := exporter.Counters()
	if counters.CircuitRejectedBatches != 2 {
		t.Fatalf("CircuitRejectedBatches = %d, want 2", counters.CircuitRejectedBatches)
	}
	if counters.CircuitRejectedRecords != 10 {
		t.Fatalf("CircuitRejectedRecords = %d, want 10 (7+3)", counters.CircuitRejectedRecords)
	}
	if counters.Accepted != 0 {
		t.Fatalf("suppressed work must not count as accepted, got %d", counters.Accepted)
	}

	// The operator-facing surface has to show the loss, not just the internal
	// counter, because Export deliberately returned nil for both batches.
	if dropped := exporter.deliveryHealthSnapshot().Counters.Dropped; dropped != 10 {
		t.Fatalf("health snapshot Dropped = %d, want 10", dropped)
	}
}

// A closed circuit must not inflate the suppression counters.
func TestMetricClosedCircuitRecordsNoSuppression(t *testing.T) {
	start := time.Date(2026, time.July, 30, 17, 0, 0, 0, time.UTC)
	inner := &metricCircuitInner{}
	exporter := sizedMetricExporter(t, inner, start, multiMetricData(4))

	if err := exporter.Export(t.Context(), multiMetricData(4)); err != nil {
		t.Fatalf("closed-circuit export error=%v", err)
	}
	counters := exporter.Counters()
	if counters.CircuitRejectedBatches != 0 || counters.CircuitRejectedRecords != 0 {
		t.Fatalf("closed circuit recorded suppression: %+v", counters)
	}
	if counters.Exported != 4 {
		t.Fatalf("Exported = %d, want 4", counters.Exported)
	}
	if dropped := exporter.deliveryHealthSnapshot().Counters.Dropped; dropped != 0 {
		t.Fatalf("health snapshot Dropped = %d, want 0", dropped)
	}
}

// Spans are counted the same way. len(spans) is O(1), so there is no reason for
// the trace route to leave its loss unquantified either.
func TestSpanOpenCircuitCountsSuppressedSpans(t *testing.T) {
	start := time.Date(2026, time.July, 31, 16, 0, 0, 0, time.UTC)
	inner := &spanCircuitInner{}
	exporter := newSpanCircuitTestExporter(t, inner, &dialOutcomeTracker{}, func() time.Time {
		return start
	})
	if !exporter.circuit.RecordFailure(delivery.FailureClassUnsafeEndpoint, start) {
		t.Fatal("unsafe-endpoint failure should open the circuit immediately")
	}

	span := testSpan("defenseclaw.trace.circuit")
	spans := []sdktrace.ReadOnlySpan{span, span, span, span, span}
	if err := exporter.ExportSpans(t.Context(), spans); err != nil {
		t.Fatalf("blocked span export should be a silent no-op, got %v", err)
	}

	if inner.calls.Load() != 0 {
		t.Fatalf("open circuit reached the inner span exporter %d times", inner.calls.Load())
	}
	counters := exporter.Counters()
	if counters.CircuitRejectedBatches != 1 {
		t.Fatalf("CircuitRejectedBatches = %d, want 1", counters.CircuitRejectedBatches)
	}
	if counters.CircuitRejectedRecords != uint64(len(spans)) {
		t.Fatalf("CircuitRejectedRecords = %d, want %d", counters.CircuitRejectedRecords, len(spans))
	}
	if dropped := exporter.deliveryHealthSnapshot().Counters.Dropped; dropped != uint64(len(spans)) {
		t.Fatalf("health snapshot Dropped = %d, want %d", dropped, len(spans))
	}
}
