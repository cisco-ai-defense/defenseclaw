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
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type metricCircuitInner struct {
	calls       atomic.Uint64
	outcomes    []error
	blockCall   uint64
	started     chan uint64
	release     <-chan struct{}
	beforeError func(uint64)
}

func (*metricCircuitInner) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (*metricCircuitInner) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(kind)
}

func (inner *metricCircuitInner) Export(ctx context.Context, _ *metricdata.ResourceMetrics) error {
	index := inner.calls.Add(1) - 1
	if inner.started != nil {
		inner.started <- index
	}
	if inner.release != nil && index == inner.blockCall {
		select {
		case <-inner.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if inner.beforeError != nil {
		inner.beforeError(index)
	}
	if index < uint64(len(inner.outcomes)) {
		return inner.outcomes[index]
	}
	return nil
}

func (*metricCircuitInner) ForceFlush(context.Context) error { return nil }
func (*metricCircuitInner) Shutdown(context.Context) error   { return nil }

func newMetricCircuitTestExporter(
	t *testing.T,
	inner sdkmetric.Exporter,
	tracker *dialOutcomeTracker,
	now func() time.Time,
) *MetricExporter {
	t.Helper()
	circuit, err := delivery.NewCircuit(delivery.CircuitPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	metrics := testMetricData("defenseclaw.metric.circuit")
	bound, ok := conservativeMetricBytes(metrics)
	if !ok {
		t.Fatal("metric test data has no conservative bound")
	}
	return &MetricExporter{
		inner: inner, maxBytes: bound, config: signalConfig{tracker: tracker},
		circuit: circuit, now: now,
	}
}

func receiveMetricCircuitCall(t *testing.T, started <-chan uint64) uint64 {
	t.Helper()
	select {
	case index := <-started:
		return index
	case <-time.After(time.Second):
		t.Fatal("metric exporter call did not start")
		return 0
	}
}

func TestMetricCircuitAuthenticationAndUnsafeFailuresOpenImmediately(t *testing.T) {
	start := time.Date(2026, time.July, 30, 16, 0, 0, 0, time.UTC)
	metrics := testMetricData("defenseclaw.metric.circuit")
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
			inner := &metricCircuitInner{outcomes: []error{test.outcome}}
			if test.prepare != nil {
				inner.beforeError = test.prepare(tracker)
			}
			exporter := newMetricCircuitTestExporter(t, inner, tracker, func() time.Time { return start })
			if err := exporter.Export(t.Context(), metrics); !IsError(err, test.errorCode) {
				t.Fatalf("first export error=%v", err)
			}
			snapshot := exporter.deliveryHealthSnapshot()
			if snapshot.State != delivery.HealthFailing ||
				snapshot.Reason != string(delivery.HealthReasonCircuitOpen) ||
				snapshot.CircuitState != delivery.CircuitOpen ||
				snapshot.ConsecutiveFailures != 1 ||
				snapshot.LastFailureClass != test.class ||
				!snapshot.CircuitOpenUntil.Equal(start.Add(24*time.Hour)) {
				t.Fatalf("open metric circuit=%+v", snapshot)
			}
			if counters := exporter.Counters(); counters.Accepted != 1 ||
				counters.Failed != 1 || counters.RejectedOversize != 0 {
				t.Fatalf("first export counters=%+v", counters)
			}

			// If admission were checked after metric counting or bounding, this
			// deliberately impossible bound would change the counters.
			exporter.maxBytes = 0
			if err := exporter.Export(t.Context(), metrics); !IsError(err, ErrorExport) {
				t.Fatalf("blocked export error=%v", err)
			}
			if inner.calls.Load() != 1 {
				t.Fatalf("open circuit invoked metric exporter %d times", inner.calls.Load())
			}
			if counters := exporter.Counters(); counters.Accepted != 1 ||
				counters.Failed != 1 || counters.RejectedOversize != 0 ||
				counters.CircuitRejectedBatches != 1 {
				t.Fatalf("blocked export performed metric work: %+v", counters)
			}
		})
	}
}

func TestMetricCircuitTransientFailuresUseDefaultThreshold(t *testing.T) {
	start := time.Date(2026, time.July, 30, 16, 30, 0, 0, time.UTC)
	inner := &metricCircuitInner{outcomes: []error{
		errors.New("transient one"),
		errors.New("transient two"),
		errors.New("transient three"),
	}}
	exporter := newMetricCircuitTestExporter(t, inner, &dialOutcomeTracker{}, func() time.Time {
		return start
	})
	metrics := testMetricData("defenseclaw.metric.circuit")
	for failure := uint64(1); failure <= 3; failure++ {
		if err := exporter.Export(t.Context(), metrics); !IsError(err, ErrorExport) {
			t.Fatalf("transient export %d error=%v", failure, err)
		}
		snapshot := exporter.deliveryHealthSnapshot()
		if snapshot.ConsecutiveFailures != failure ||
			snapshot.LastFailureClass != delivery.FailureClassTransient {
			t.Fatalf("transient failure %d circuit=%+v", failure, snapshot)
		}
		if failure < 3 && snapshot.CircuitState != delivery.CircuitClosed {
			t.Fatalf("circuit opened before default threshold: %+v", snapshot)
		}
		if failure == 3 &&
			(snapshot.CircuitState != delivery.CircuitOpen ||
				!snapshot.CircuitOpenUntil.Equal(start.Add(30*time.Second))) {
			t.Fatalf("default-threshold circuit=%+v", snapshot)
		}
	}
	if err := exporter.Export(t.Context(), metrics); !IsError(err, ErrorExport) {
		t.Fatalf("blocked transient export error=%v", err)
	}
	if inner.calls.Load() != 3 {
		t.Fatalf("open transient circuit invoked exporter %d times", inner.calls.Load())
	}
	if exporter.Counters().CircuitRejectedBatches != 1 {
		t.Fatalf("blocked transient accounting=%+v", exporter.Counters())
	}
}

func TestMetricCircuitHalfOpenAdmitsExactlyOneConcurrentProbe(t *testing.T) {
	start := time.Date(2026, time.July, 30, 17, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	release := make(chan struct{})
	const blocked = 32
	inner := &metricCircuitInner{
		outcomes: []error{
			status.Error(codes.Unauthenticated, "denied"),
			nil,
			nil,
		},
		blockCall: 1,
		started:   make(chan uint64, blocked+3),
		release:   release,
	}
	exporter := newMetricCircuitTestExporter(t, inner, &dialOutcomeTracker{}, func() time.Time {
		return time.Unix(0, clock.Load()).UTC()
	})
	metrics := testMetricData("defenseclaw.metric.circuit")
	if err := exporter.Export(t.Context(), metrics); !IsError(err, ErrorExport) {
		t.Fatalf("authentication export error=%v", err)
	}
	if index := receiveMetricCircuitCall(t, inner.started); index != 0 {
		t.Fatalf("first exporter call index=%d", index)
	}
	opened := exporter.deliveryHealthSnapshot()
	if opened.CircuitState != delivery.CircuitOpen {
		t.Fatalf("initial circuit=%+v", opened)
	}
	clock.Store(opened.CircuitOpenUntil.UnixNano())

	probeDone := make(chan error, 1)
	go func() {
		probeDone <- exporter.Export(context.Background(), metrics)
	}()
	if index := receiveMetricCircuitCall(t, inner.started); index != 1 {
		t.Fatalf("probe exporter call index=%d", index)
	}

	var wait sync.WaitGroup
	wait.Add(blocked)
	blockedErrors := make(chan error, blocked)
	for index := 0; index < blocked; index++ {
		go func() {
			defer wait.Done()
			blockedErrors <- exporter.Export(context.Background(), metrics)
		}()
	}
	waitDone := make(chan struct{})
	go func() {
		wait.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("concurrent blocked metric exports did not return")
	}
	close(blockedErrors)
	for err := range blockedErrors {
		if !IsError(err, ErrorExport) {
			t.Fatalf("concurrent blocked export error=%v", err)
		}
	}
	if inner.calls.Load() != 2 {
		t.Fatalf("half-open circuit admitted %d exporter calls", inner.calls.Load()-1)
	}
	if exporter.Counters().CircuitRejectedBatches != blocked {
		t.Fatalf("half-open rejection accounting=%+v", exporter.Counters())
	}
	halfOpen := exporter.deliveryHealthSnapshot()
	if halfOpen.CircuitState != delivery.CircuitHalfOpen ||
		halfOpen.State != delivery.HealthDegraded ||
		halfOpen.Reason != string(delivery.HealthReasonCircuitHalfOpen) {
		t.Fatalf("half-open metric circuit=%+v", halfOpen)
	}

	close(release)
	select {
	case err := <-probeDone:
		if err != nil {
			t.Fatalf("successful probe error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("successful half-open probe did not return")
	}
	recovered := exporter.deliveryHealthSnapshot()
	if recovered.CircuitState != delivery.CircuitClosed ||
		recovered.ConsecutiveFailures != 0 ||
		!recovered.CircuitOpenUntil.IsZero() ||
		recovered.LastFailureClass != delivery.FailureClassAuthentication ||
		recovered.State != delivery.HealthHealthy {
		t.Fatalf("recovered metric circuit=%+v", recovered)
	}
	if err := exporter.Export(t.Context(), metrics); err != nil {
		t.Fatalf("post-recovery export error=%v", err)
	}
	if inner.calls.Load() != 3 {
		t.Fatalf("post-recovery exporter calls=%d", inner.calls.Load())
	}
}

func TestMetricCircuitTracksHTTPAuthenticationWithoutRetry(t *testing.T) {
	var calls atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	factory := prepareTestFactory(t, Config{
		Destination: "metric-circuit-http-auth", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalMetrics}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	exporter, err := factory.NewMetricExporter(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	metrics := testMetricData("defenseclaw.metric.circuit")
	if err := exporter.Export(t.Context(), metrics); !IsError(err, ErrorExport) {
		t.Fatalf("authentication export error=%v", err)
	}
	snapshot := exporter.deliveryHealthSnapshot()
	if snapshot.CircuitState != delivery.CircuitOpen ||
		snapshot.LastFailureClass != delivery.FailureClassAuthentication ||
		snapshot.Reason != string(delivery.HealthReasonCircuitOpen) {
		t.Fatalf("HTTP authentication circuit=%+v", snapshot)
	}
	if err := exporter.Export(t.Context(), metrics); !IsError(err, ErrorExport) {
		t.Fatalf("blocked HTTP export error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("open HTTP authentication circuit made %d requests", calls.Load())
	}
	if exporter.Counters().CircuitRejectedBatches != 1 {
		t.Fatalf("HTTP authentication rejection accounting=%+v", exporter.Counters())
	}
	if err := exporter.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestMetricLocalOversizeDoesNotAdvanceOrStrandCircuit(t *testing.T) {
	start := time.Date(2026, time.July, 30, 18, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	inner := &metricCircuitInner{outcomes: []error{
		status.Error(codes.Unauthenticated, "denied"),
		nil,
	}}
	exporter := newMetricCircuitTestExporter(t, inner, &dialOutcomeTracker{}, func() time.Time {
		return time.Unix(0, clock.Load()).UTC()
	})
	metrics := testMetricData("defenseclaw.metric.circuit")
	if err := exporter.Export(t.Context(), metrics); !IsError(err, ErrorExport) {
		t.Fatalf("authentication export error=%v", err)
	}
	opened := exporter.deliveryHealthSnapshot()
	clock.Store(opened.CircuitOpenUntil.UnixNano())
	maxBytes := exporter.maxBytes
	exporter.maxBytes = 0
	if err := exporter.Export(t.Context(), metrics); !IsError(err, ErrorExport) {
		t.Fatalf("local oversize error=%v", err)
	}
	afterLocal := exporter.deliveryHealthSnapshot()
	if afterLocal.CircuitState != delivery.CircuitOpen ||
		afterLocal.ConsecutiveFailures != 1 ||
		afterLocal.LastFailureClass != delivery.FailureClassAuthentication ||
		!afterLocal.CircuitOpenUntil.Equal(opened.CircuitOpenUntil) ||
		afterLocal.Reason != string(delivery.HealthReasonDeliveryFailed) {
		t.Fatalf("local oversize changed destination circuit=%+v", afterLocal)
	}
	if inner.calls.Load() != 1 || exporter.Counters().RejectedOversize != 1 {
		t.Fatalf("local oversize work calls=%d counters=%+v", inner.calls.Load(), exporter.Counters())
	}

	exporter.maxBytes = maxBytes
	if err := exporter.Export(t.Context(), metrics); err != nil {
		t.Fatalf("probe after local oversize error=%v", err)
	}
	recovered := exporter.deliveryHealthSnapshot()
	if recovered.CircuitState != delivery.CircuitClosed ||
		recovered.ConsecutiveFailures != 0 ||
		inner.calls.Load() != 2 {
		t.Fatalf("probe after local oversize=%+v calls=%d", recovered, inner.calls.Load())
	}
}

func TestMetricObserverCanShutdownWithoutLockInversion(t *testing.T) {
	start := time.Date(2026, time.July, 30, 18, 30, 0, 0, time.UTC)
	inner := &metricCircuitInner{outcomes: []error{
		status.Error(codes.Unauthenticated, "denied"),
	}}
	exporter := newMetricCircuitTestExporter(t, inner, &dialOutcomeTracker{}, func() time.Time {
		return start
	})
	observerDone := make(chan error, 1)
	exporter.config.observer = SignalObserverFunc(func(event SignalEvent) {
		if event.Outcome != SignalOutcomeExportFailed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		observerDone <- exporter.Shutdown(ctx)
	})
	exportDone := make(chan error, 1)
	go func() {
		exportDone <- exporter.Export(context.Background(), testMetricData("defenseclaw.metric.circuit"))
	}()
	select {
	case err := <-observerDone:
		if err != nil {
			t.Fatalf("observer shutdown error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("metric observer deadlocked while shutting down exporter")
	}
	select {
	case err := <-exportDone:
		if !IsError(err, ErrorExport) {
			t.Fatalf("export error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("metric export did not return after observer shutdown")
	}
	if snapshot := exporter.deliveryHealthSnapshot(); snapshot.State != delivery.HealthStopped ||
		snapshot.CircuitState != delivery.CircuitOpen {
		t.Fatalf("post-observer shutdown health=%+v", snapshot)
	}
}
