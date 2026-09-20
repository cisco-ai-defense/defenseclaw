// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"go.opentelemetry.io/otel/trace"
)

func TestWatcherMetricsV8PreserveFamiliesLabelsAndCorrelation(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	explicitTraceID := "0123456789abcdef0123456789abcdef"
	activeTraceID, err := trace.TraceIDFromHex(explicitTraceID)
	if err != nil {
		t.Fatal(err)
	}
	activeSpanID, err := trace.SpanIDFromHex("bbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithEnvelope(context.Background(), CorrelationEnvelope{
		RunID: "watcher-run-1", TraceID: explicitTraceID,
		RequestID: "watcher-request-1", Connector: "codex",
	})
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: activeTraceID, SpanID: activeSpanID, TraceFlags: trace.FlagsSampled,
	}))

	calls := []func() error{
		func() error { return logger.RecordWatcherEventMetric(ctx, "rescan_scan", "skill", "codex") },
		func() error { return logger.RecordWatcherErrorMetric(ctx) },
		func() error { return logger.RecordAdmissionDecisionMetric(ctx, "blocked", "skill", "watcher") },
		func() error { return logger.RecordWatcherScanErrorMetric(ctx, "skill-scanner", "skill", "timeout") },
		func() error { return logger.RecordQuarantineActionMetric(ctx, "move_in", "error") },
		func() error { return logger.RecordBlockSLOMetric(ctx, "skill", 37.5) },
		func() error { return logger.RecordProvenanceBumpMetric(ctx, "policy_files") },
	}
	for index, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("metric call %d: %v", index, err)
		}
	}

	metrics := runtime.metricSnapshot()
	want := []struct {
		family observability.EventName
		bucket observability.Bucket
		value  string
		attrs  map[string]string
	}{
		{
			observability.EventName(observability.TelemetryInstrumentDefenseClawWatcherEvents),
			observability.BucketAssetLifecycle, "1", map[string]string{
				"defenseclaw.connector.source":   "codex",
				"defenseclaw.metric.event_type":  "rescan_scan",
				"defenseclaw.metric.target_type": "skill",
			},
		},
		{observability.EventName(observability.TelemetryInstrumentDefenseClawWatcherErrors), observability.BucketAssetLifecycle, "1", map[string]string{}},
		{
			observability.EventName(observability.TelemetryInstrumentDefenseClawAdmissionDecisions),
			observability.BucketGuardrailEvaluation, "1", map[string]string{
				"defenseclaw.metric.decision":    "blocked",
				"defenseclaw.metric.source":      "watcher",
				"defenseclaw.metric.target_type": "skill",
			},
		},
		{
			observability.EventName(observability.TelemetryInstrumentDefenseClawScanErrors),
			observability.BucketAssetScan, "1", map[string]string{
				"defenseclaw.metric.error_type":  "timeout",
				"defenseclaw.metric.target_type": "skill",
				"defenseclaw.scan.scanner":       "skill-scanner",
			},
		},
		{
			observability.EventName(observability.TelemetryInstrumentDefenseClawQuarantineActions),
			observability.BucketEnforcementAction, "1", map[string]string{
				"defenseclaw.metric.quarantine.op":     "move_in",
				"defenseclaw.metric.quarantine.result": "error",
			},
		},
		{
			observability.EventName(observability.TelemetryInstrumentDefenseClawSloBlockLatency),
			observability.BucketPlatformHealth, "37.5", map[string]string{
				"defenseclaw.metric.target_type": "skill",
			},
		},
		{
			observability.EventName(observability.TelemetryInstrumentDefenseClawProvenanceBumps),
			observability.BucketDiagnostic, "1", map[string]string{
				"defenseclaw.metric.reason": "policy_files",
			},
		},
	}
	if len(metrics) != len(want) {
		t.Fatalf("generated metrics = %d, want %d", len(metrics), len(want))
	}
	for index, record := range metrics {
		if record.EventName() != want[index].family || record.Bucket() != want[index].bucket ||
			record.Signal() != observability.SignalMetrics {
			t.Fatalf("metric %d identity = %s/%s/%s, want %s/%s/metrics", index,
				record.Bucket(), record.Signal(), record.EventName(), want[index].bucket, want[index].family)
		}
		value, attrs := watcherMetricValueAndAttributes(t, record)
		if value != want[index].value || !reflect.DeepEqual(attrs, want[index].attrs) {
			t.Fatalf("metric %d value/attrs = %q/%#v, want %q/%#v", index,
				value, attrs, want[index].value, want[index].attrs)
		}
		correlation := record.Correlation()
		if correlation.RunID != "watcher-run-1" || correlation.RequestID != "watcher-request-1" ||
			correlation.TraceID != explicitTraceID || correlation.SpanID != activeSpanID.String() ||
			correlation.ConnectorID != "codex" {
			t.Fatalf("metric %d correlation = %#v", index, correlation)
		}
	}
}

func TestWatcherMetricsV8DetachFailsClosedWithoutFallback(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	logger.SetRuntimeV8Emitter(nil)

	if err := logger.RecordWatcherEventMetric(t.Context(), "create", "skill", ""); err == nil {
		t.Fatal("detached authoritative runtime accepted a watcher metric")
	}
	if got := len(runtime.metricSnapshot()); got != 0 {
		t.Fatalf("detached runtime received %d watcher metrics", got)
	}
}

func TestWatcherMetricsV8NeverMixTraceAndSpanFromDifferentContexts(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	activeTraceID, err := trace.TraceIDFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	activeSpanID, err := trace.SpanIDFromHex("bbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithEnvelope(t.Context(), CorrelationEnvelope{
		TraceID: "0123456789abcdef0123456789abcdef",
	})
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: activeTraceID, SpanID: activeSpanID,
	}))
	if err := logger.RecordWatcherErrorMetric(ctx); err != nil {
		t.Fatal(err)
	}
	metrics := runtime.metricSnapshot()
	if len(metrics) != 1 {
		t.Fatalf("metrics = %d, want 1", len(metrics))
	}
	correlation := metrics[0].Correlation()
	if correlation.TraceID != "0123456789abcdef0123456789abcdef" || correlation.SpanID != "" {
		t.Fatalf("mixed correlation from different W3C contexts: %#v", correlation)
	}
}

func watcherMetricValueAndAttributes(
	t *testing.T,
	record observability.Record,
) (string, map[string]string) {
	t.Helper()
	instrument, present := record.InstrumentData()
	if !present {
		t.Fatal("metric instrument data is absent")
	}
	data, err := instrument.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes, ok := data["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("metric attributes = %#v", data["attributes"])
	}
	result := make(map[string]string, len(attributes))
	for key, value := range attributes {
		result[key] = fmt.Sprint(value)
	}
	return fmt.Sprint(data["value"]), result
}
