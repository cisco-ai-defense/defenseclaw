// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

func platformHealthCorrelatedContext(t *testing.T) (context.Context, trace.SpanContext) {
	t.Helper()
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		SpanID:  trace.SpanID{24, 23, 22, 21, 20, 19, 18, 17},
	})
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{
		RunID: "run-platform", RequestID: "request-platform", SessionID: "session-platform",
		TurnID: "turn-platform", AgentID: "agent-platform", ToolID: "tool-platform",
		PolicyID: "policy-platform", Connector: "codex",
	})
	return trace.ContextWithSpanContext(ctx, spanContext), spanContext
}

func generatedMetricByName(
	metrics []telemetry.V8ProjectedMetric,
	name string,
) []telemetry.V8ProjectedMetric {
	var result []telemetry.V8ProjectedMetric
	for _, metric := range metrics {
		if metric.Descriptor().Name == name {
			result = append(result, metric)
		}
	}
	return result
}

func TestRecordAuditDBErrorV8PreservesOperationAndCorrelation(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, parent := platformHealthCorrelatedContext(t)

	recordAuditDBErrorV8(ctx, runtime, "emit_asset_policy")

	metrics := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawAuditDBErrors)
	if len(metrics) != 1 {
		t.Fatalf("generated audit DB error metrics=%d", len(metrics))
	}
	if attributes := metrics[0].Attributes(); attributes["defenseclaw.metric.operation"] != "emit_asset_policy" {
		t.Fatalf("generated audit DB error attributes=%v", attributes)
	}
	gatewayErrors := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawGatewayErrors,
	)
	if len(gatewayErrors) != 1 ||
		gatewayErrors[0].Attributes()["defenseclaw.metric.error.subsystem"] != "audit" ||
		gatewayErrors[0].Attributes()["defenseclaw.metric.error.code"] != "AUDIT_DB_ERROR" {
		t.Fatalf("generated gateway audit errors=%v", gatewayErrors)
	}
	correlation := metrics[0].CanonicalRecord().Correlation()
	if correlation.TraceID != parent.TraceID().String() || correlation.SpanID != parent.SpanID().String() ||
		correlation.RequestID != "request-platform" || correlation.SessionID != "session-platform" ||
		correlation.TurnID != "turn-platform" || correlation.AgentID != "agent-platform" ||
		correlation.PolicyID != "policy-platform" || correlation.ToolInvocationID != "tool-platform" {
		t.Fatalf("generated audit DB error correlation=%+v", correlation)
	}
}

func TestGatewayPanicV8EmitsCorrelatedMetricAndDurableHealthRecord(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, spanContext := platformHealthCorrelatedContext(t)

	observedAt := time.Now().UTC()
	recordGatewayPanicMetricV8(ctx, runtime, observedAt)
	if err := emitGatewayPanicHealthV8(ctx, runtime, observedAt); err != nil {
		t.Fatal(err)
	}

	metrics := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawPanicsTotal,
	)
	if len(metrics) != 1 {
		t.Fatalf("panic metric count=%d", len(metrics))
	}
	gatewayErrors := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawGatewayErrors,
	)
	if len(gatewayErrors) != 1 ||
		gatewayErrors[0].Attributes()["defenseclaw.metric.error.subsystem"] != "gateway" ||
		gatewayErrors[0].Attributes()["defenseclaw.metric.error.code"] != string(gatewaylog.ErrCodePanicRecovered) {
		t.Fatalf("generated gateway panic errors=%v", gatewayErrors)
	}
	metric := metrics[0]
	if metric.Attributes()["defenseclaw.metric.subsystem"] != "gateway" ||
		metric.CanonicalRecord().Source() != observability.SourceGateway {
		t.Fatalf("panic metric source/attributes=%s/%v", metric.CanonicalRecord().Source(), metric.Attributes())
	}
	correlation := metric.CanonicalRecord().Correlation()
	if correlation.TraceID != spanContext.TraceID().String() ||
		correlation.SpanID != spanContext.SpanID().String() ||
		correlation.RequestID != "request-platform" || correlation.SessionID != "session-platform" ||
		correlation.TurnID != "turn-platform" || correlation.AgentID != "agent-platform" ||
		correlation.ToolInvocationID != "tool-platform" || correlation.PolicyID != "policy-platform" {
		t.Fatalf("panic metric correlation=%+v", correlation)
	}

	database, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var mandatory int
	var raw string
	if err := database.QueryRowContext(ctx, `SELECT mandatory, projected_record_json FROM audit_events
		WHERE bucket = 'platform.health' AND event_name = 'subsystem.degraded' AND action = 'error'`).Scan(
		&mandatory, &raw,
	); err != nil {
		t.Fatal(err)
	}
	if mandatory != 1 {
		t.Fatalf("panic health mandatory=%d", mandatory)
	}
	var projected struct {
		Correlation observability.Correlation `json:"correlation"`
		Body        map[string]any            `json:"body"`
	}
	if err := json.Unmarshal([]byte(raw), &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Correlation.TraceID != correlation.TraceID ||
		projected.Correlation.SpanID != correlation.SpanID ||
		projected.Body["defenseclaw.health.subsystem"] != "gateway" ||
		projected.Body["defenseclaw.health.state"] != "failed" ||
		projected.Body["defenseclaw.schema.error_code"] != "PANIC_RECOVERED" {
		t.Fatalf("panic health projection=%+v", projected)
	}
	if _, leaked := projected.Body["exception.message"]; leaked {
		t.Fatalf("panic health projection leaked exception content: %v", projected.Body)
	}
}

func TestWatcherV8MetricsUseCanonicalFamiliesAndWatcherSource(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, spanContext := platformHealthCorrelatedContext(t)

	recordWatcherErrorV8(ctx, runtime)
	recordWatcherEventV8(ctx, runtime, "hook-heal", "codex", "codex")
	recordWatcherRestartV8(ctx, runtime)

	metrics := capture.metricSnapshot()
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawWatcherErrors,
		observability.TelemetryInstrumentDefenseClawWatcherEvents,
		observability.TelemetryInstrumentDefenseClawWatcherRestarts,
	} {
		family := generatedMetricByName(metrics, name)
		if len(family) != 1 {
			t.Fatalf("watcher metric %s count=%d all=%v", name, len(family), metrics)
		}
		if family[0].CanonicalRecord().Source() != observability.SourceWatcher {
			t.Fatalf("watcher metric %s source=%s", name, family[0].CanonicalRecord().Source())
		}
		correlation := family[0].CanonicalRecord().Correlation()
		if correlation.TraceID != spanContext.TraceID().String() ||
			correlation.SpanID != spanContext.SpanID().String() ||
			correlation.RequestID != "request-platform" {
			t.Fatalf("watcher metric %s correlation=%+v", name, correlation)
		}
	}
	event := generatedMetricByName(metrics, observability.TelemetryInstrumentDefenseClawWatcherEvents)[0]
	if event.CanonicalRecord().Connector() != "codex" ||
		event.Attributes()["defenseclaw.connector.source"] != "codex" ||
		event.Attributes()["defenseclaw.metric.event_type"] != "hook-heal" ||
		event.Attributes()["defenseclaw.metric.target_type"] != "codex" {
		t.Fatalf("watcher event connector/attributes=%q/%v", event.CanonicalRecord().Connector(), event.Attributes())
	}
	gatewayErrors := generatedMetricByName(
		metrics, observability.TelemetryInstrumentDefenseClawGatewayErrors,
	)
	if len(gatewayErrors) != 1 ||
		gatewayErrors[0].Attributes()["defenseclaw.metric.error.subsystem"] != "watcher" ||
		gatewayErrors[0].Attributes()["defenseclaw.metric.error.code"] != "WATCHER_ERROR" {
		t.Fatalf("generated watcher gateway errors=%v", gatewayErrors)
	}
}

func TestConfigLoadErrorV8UsesCanonicalFamilyAndCorrelation(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, spanContext := platformHealthCorrelatedContext(t)

	recordConfigLoadErrorV8(ctx, runtime, "candidate_invalid")

	metrics := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawConfigLoadErrors,
	)
	if len(metrics) != 1 ||
		metrics[0].Attributes()["defenseclaw.metric.error_type"] != "candidate_invalid" ||
		metrics[0].CanonicalRecord().Source() != observability.SourceSystem ||
		metrics[0].CanonicalRecord().Provenance().Producer != configMetricV8Producer {
		t.Fatalf("generated config load errors=%v", metrics)
	}
	correlation := metrics[0].CanonicalRecord().Correlation()
	if correlation.TraceID != spanContext.TraceID().String() ||
		correlation.SpanID != spanContext.SpanID().String() ||
		correlation.RequestID != "request-platform" {
		t.Fatalf("config load error correlation=%+v", correlation)
	}
}

func TestWatchdogRecoveryEndpointRecordsCanonicalMetricAndRejectsRemoteCallers(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/watchdog/recovery", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	response := httptest.NewRecorder()
	api.handleWatchdogRecovery(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("loopback recovery status=%d body=%s", response.Code, response.Body.String())
	}
	if metrics := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWatcherRestarts); len(metrics) != 1 {
		t.Fatalf("canonical watcher restart metrics=%d", len(metrics))
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/watchdog/recovery", nil)
	request.RemoteAddr = "203.0.113.9:43210"
	response = httptest.NewRecorder()
	api.handleWatchdogRecovery(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("remote recovery status=%d body=%s", response.Code, response.Body.String())
	}
	if metrics := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWatcherRestarts); len(metrics) != 1 {
		t.Fatalf("remote recovery mutated canonical metrics=%d", len(metrics))
	}
}
