// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"go.opentelemetry.io/otel/trace"
)

func TestOpenShellExitMetricV8PreservesLabelsAndCorrelation(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	traceID, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("bbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithEnvelope(context.Background(), CorrelationEnvelope{
		RunID: "openshell-run-1", RequestID: "openshell-request-1", Connector: "codex",
	})
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
	if err := logger.RecordOpenShellExitMetric(ctx, "openshell policy reload", 7); err != nil {
		t.Fatal(err)
	}

	logs, metrics := runtime.snapshot()
	if len(logs) != 0 || len(metrics) != 1 {
		t.Fatalf("generated logs/metrics = %d/%d", len(logs), len(metrics))
	}
	record := metrics[0]
	if record.EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawOpenshellExit) ||
		record.Bucket() != observability.BucketToolActivity || record.Signal() != observability.SignalMetrics {
		t.Fatalf("metric identity = %s/%s/%s", record.Bucket(), record.Signal(), record.EventName())
	}
	value, attributes := watcherMetricValueAndAttributes(t, record)
	wantAttributes := map[string]string{
		"defenseclaw.metric.command": "openshell policy reload",
		"defenseclaw.tool.exit_code": "7",
	}
	if value != "1" || !reflect.DeepEqual(attributes, wantAttributes) {
		t.Fatalf("metric value/attributes = %q/%#v", value, attributes)
	}
	correlation := record.Correlation()
	if correlation.RunID != "openshell-run-1" || correlation.RequestID != "openshell-request-1" ||
		correlation.TraceID != traceID.String() || correlation.SpanID != spanID.String() ||
		correlation.ConnectorID != "codex" {
		t.Fatalf("metric correlation = %#v", correlation)
	}
}

func TestOpenShellExitMetricV8DetachFailsClosed(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	logger.SetRuntimeV8Emitter(nil)
	if err := logger.RecordOpenShellExitMetric(t.Context(), "openshell start", 127); err == nil {
		t.Fatal("detached authoritative runtime accepted an OpenShell metric")
	}
	_, metrics := runtime.snapshot()
	if len(metrics) != 0 {
		t.Fatalf("detached runtime received %d OpenShell metrics", len(metrics))
	}
}
