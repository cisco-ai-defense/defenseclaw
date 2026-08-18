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
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type spanCircuitInner struct {
	calls       atomic.Uint64
	outcomes    []error
	beforeError func(uint64)
}

func (inner *spanCircuitInner) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	index := inner.calls.Add(1) - 1
	if inner.beforeError != nil {
		inner.beforeError(index)
	}
	if index < uint64(len(inner.outcomes)) {
		return inner.outcomes[index]
	}
	return nil
}

func (*spanCircuitInner) Shutdown(context.Context) error { return nil }

func newSpanCircuitTestExporter(
	t *testing.T,
	inner sdktrace.SpanExporter,
	tracker *dialOutcomeTracker,
	now func() time.Time,
) *SpanExporter {
	t.Helper()
	circuit, err := delivery.NewCircuit(delivery.CircuitPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	span := testSpan("defenseclaw.trace.circuit")
	bound, ok := conservativeSpanBytes(span)
	if !ok {
		t.Fatal("trace test data has no conservative bound")
	}
	return &SpanExporter{
		inner: inner, maxBytes: bound, destination: "trace-circuit",
		config: signalConfig{tracker: tracker}, circuit: circuit, now: now,
	}
}

func TestSpanCircuitAuthenticationAndUnsafeFailuresOpenImmediately(t *testing.T) {
	start := time.Date(2026, time.July, 31, 16, 0, 0, 0, time.UTC)
	span := testSpan("defenseclaw.trace.circuit")
	tests := []struct {
		name      string
		outcome   error
		class     delivery.FailureClass
		errorCode ErrorCode
		prepare   func(*dialOutcomeTracker) func(uint64)
	}{
		{
			name: "authentication", outcome: status.Error(codes.Unauthenticated, "denied"),
			class: delivery.FailureClassAuthentication, errorCode: ErrorExport,
		},
		{
			name: "unsafe-endpoint", outcome: errors.New("unsafe"),
			class: delivery.FailureClassUnsafeEndpoint, errorCode: ErrorUnsafeEndpoint,
			prepare: func(tracker *dialOutcomeTracker) func(uint64) {
				return func(uint64) { tracker.record(netguard.ErrV8AddressProhibited) }
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tracker := &dialOutcomeTracker{}
			inner := &spanCircuitInner{outcomes: []error{test.outcome}}
			if test.prepare != nil {
				inner.beforeError = test.prepare(tracker)
			}
			exporter := newSpanCircuitTestExporter(t, inner, tracker, func() time.Time { return start })
			if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{span}); !IsError(err, test.errorCode) {
				t.Fatalf("first export error = %v", err)
			}
			if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{span}); err != nil {
				t.Fatalf("open-circuit rejection should be a silent no-op: %v", err)
			}
			if inner.calls.Load() != 1 || exporter.Counters().CircuitRejectedBatches != 1 {
				t.Fatalf("calls=%d counters=%+v", inner.calls.Load(), exporter.Counters())
			}
			snapshot := exporter.deliveryHealthSnapshot()
			if snapshot.CircuitState != delivery.CircuitOpen ||
				snapshot.LastFailureClass != test.class ||
				snapshot.Reason != string(delivery.HealthReasonCircuitOpen) {
				t.Fatalf("trace circuit health = %+v", snapshot)
			}
		})
	}
}

func TestSpanCircuitTransientThresholdHalfOpenRecoveryAndHealthSource(t *testing.T) {
	start := time.Date(2026, time.July, 31, 17, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	inner := &spanCircuitInner{outcomes: []error{
		errors.New("temporary-1"), errors.New("temporary-2"), errors.New("temporary-3"), nil,
	}}
	exporter := newSpanCircuitTestExporter(t, inner, &dialOutcomeTracker{}, func() time.Time {
		return time.Unix(0, clock.Load()).UTC()
	})
	span := testSpan("defenseclaw.trace.circuit")
	for failure := 0; failure < 3; failure++ {
		if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{span}); !IsError(err, ErrorExport) {
			t.Fatalf("failure %d error = %v", failure+1, err)
		}
	}
	opened := exporter.deliveryHealthSnapshot()
	if opened.CircuitState != delivery.CircuitOpen || opened.ConsecutiveFailures != 3 {
		t.Fatalf("opened trace circuit = %+v", opened)
	}
	if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{span}); err != nil {
		t.Fatalf("blocked trace export = %v", err)
	}
	clock.Store(opened.CircuitOpenUntil.UnixNano())
	if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{span}); err != nil {
		t.Fatalf("half-open recovery export = %v", err)
	}
	recovered := exporter.deliveryHealthSnapshot()
	if recovered.CircuitState != delivery.CircuitClosed ||
		recovered.State != delivery.HealthHealthy || recovered.ConsecutiveFailures != 0 {
		t.Fatalf("recovered trace circuit = %+v", recovered)
	}
	source, err := exporter.DeliveryHealthSource(7)
	if err != nil {
		t.Fatal(err)
	}
	published := source.DeliveryHealthSnapshot()
	if published.Destination != "trace-circuit" || published.Generation != 7 || published.Signal != "traces" {
		t.Fatalf("published trace health = %+v", published)
	}
}
