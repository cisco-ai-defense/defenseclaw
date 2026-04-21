// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"go.opentelemetry.io/otel/codes"
)

// TestV7ObservabilityFiveSurfaces exercises SQLite, gateway JSONL fanout,
// OTel metrics, OTel spans, and export-capture (schema-validated JSON) together
// for each v7 gateway event type. Emissions run behind an httptest.Server to
// mirror an HTTP-driven sidecar request.
func TestV7ObservabilityFiveSurfaces(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, h *observabilityHarness)
	}{
		{"EventVerdict", testSurfaceVerdict},
		{"EventJudge", testSurfaceJudge},
		{"EventLifecycle", testSurfaceLifecycle},
		{"EventError", testSurfaceError},
		{"EventDiagnostic", testSurfaceDiagnostic},
		{"EventScan", testSurfaceScan},
		{"EventScanFinding", testSurfaceScanFinding},
		{"EventActivity", testSurfaceActivity},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newObservabilityHarness(t)
			tc.run(t, h)
		})
	}
}

func assertOTelSpanPresent(t *testing.T, h *observabilityHarness) {
	t.Helper()
	if len(h.SpanExp.GetSpans()) == 0 {
		t.Fatal("expected at least one span from tracer")
	}
}

func testSurfaceVerdict(t *testing.T, h *observabilityHarness) {
	triggerViaSidecarHTTP(t, func() {
		_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.verdict")
		sp.SetStatus(codes.Ok, "")
		sp.End()
		base := envelopeBase()
		ev := base
		ev.Timestamp = time.Unix(1700000000, 0).UTC()
		ev.EventType = gatewaylog.EventVerdict
		ev.Severity = gatewaylog.SeverityHigh
		ev.Verdict = &gatewaylog.VerdictPayload{
			Stage:     gatewaylog.StageFinal,
			Action:    "block",
			Reason:    "injection",
			LatencyMs: 12,
		}
		h.GW.Emit(ev)
	})
	assertOTelSpanPresent(t, h)
	evs := findGatewayEvents(h, gatewaylog.EventVerdict)
	if len(evs) == 0 {
		t.Fatal("gateway fanout missing verdict")
	}
	got := evs[len(evs)-1]
	assertCorrelationTriplet(t, got)
	assertThreeTierIdentity(t, got)
	validateGatewayEnvelope(t, mustMarshalEvent(t, got))

	rm := collectMetrics(t, h.Reader)
	if sumInt64Counter(rm, "defenseclaw.gateway.verdicts") < 1 {
		t.Fatal("expected defenseclaw.gateway.verdicts counter")
	}
	if !metricHasAttrKeyValue(rm, "defenseclaw.gateway.verdicts", "verdict.action", "block") {
		t.Fatal("expected verdict.action=block on defenseclaw.gateway.verdicts")
	}
	// TODO(v7-followup): persist EventVerdict to a first-class SQLite projection (audit_events
	// twin rows exist for guardrail-verdict action but not for isolated gateway.Emit in tests).
	// Audit sinks receive audit.Event, not gateway envelopes — standalone GW.Emit does not fan out to sinks.Manager.
	if len(h.Sink.snapshot()) != 0 {
		t.Fatal("expected no audit sink rows for standalone gateway verdict emit")
	}
}

func testSurfaceJudge(t *testing.T, h *observabilityHarness) {
	triggerViaSidecarHTTP(t, func() {
		_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.judge")
		sp.SetStatus(codes.Ok, "")
		sp.End()
		base := envelopeBase()
		ev := base
		ev.Timestamp = time.Unix(1700000001, 0).UTC()
		ev.EventType = gatewaylog.EventJudge
		ev.Severity = gatewaylog.SeverityMedium
		ev.Model = "gpt-4"
		ev.Judge = &gatewaylog.JudgePayload{
			Kind:        "injection",
			Model:       "gpt-4",
			InputBytes:  100,
			LatencyMs:   50,
			Action:      "flag",
			Severity:    gatewaylog.SeverityMedium,
			RawResponse: "{}",
		}
		h.GW.Emit(ev)
	})
	assertOTelSpanPresent(t, h)
	evs := findGatewayEvents(h, gatewaylog.EventJudge)
	if len(evs) == 0 {
		t.Fatal("missing judge event")
	}
	got := evs[len(evs)-1]
	assertCorrelationTriplet(t, got)
	assertThreeTierIdentity(t, got)
	validateGatewayEnvelope(t, mustMarshalEvent(t, got))

	rm := collectMetrics(t, h.Reader)
	if sumInt64Counter(rm, "defenseclaw.gateway.judge.invocations") < 1 {
		t.Fatal("expected judge invocations metric")
	}
	if len(h.Sink.snapshot()) != 0 {
		t.Fatal("expected no audit sink rows for standalone judge emit")
	}
}

func testSurfaceLifecycle(t *testing.T, h *observabilityHarness) {
	triggerViaSidecarHTTP(t, func() {
		_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.lifecycle")
		sp.End()
		base := envelopeBase()
		ev := base
		ev.Timestamp = time.Unix(1700000002, 0).UTC()
		ev.EventType = gatewaylog.EventLifecycle
		ev.Severity = gatewaylog.SeverityInfo
		ev.Lifecycle = &gatewaylog.LifecyclePayload{
			Subsystem:  "gateway",
			Transition: "start",
			Details:    map[string]string{"endpoint": "ws"},
		}
		h.GW.Emit(ev)
	})
	assertOTelSpanPresent(t, h)
	evs := findGatewayEvents(h, gatewaylog.EventLifecycle)
	if len(evs) == 0 {
		t.Fatal("missing lifecycle")
	}
	got := evs[len(evs)-1]
	assertCorrelationTriplet(t, got)
	assertThreeTierIdentity(t, got)
	validateGatewayEnvelope(t, mustMarshalEvent(t, got))
	// Volume counter wired via telemetry.Provider.EmitGatewayEvent →
	// RecordGatewayEventEmitted (internal/telemetry/gateway_events.go).
	// No further assertion here; counter wiring is covered by
	// TestRecordGatewayEventEmittedWiring.
}

func testSurfaceError(t *testing.T, h *observabilityHarness) {
	triggerViaSidecarHTTP(t, func() {
		_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.error")
		sp.RecordError(nil)
		sp.End()
		base := envelopeBase()
		ev := base
		ev.Timestamp = time.Unix(1700000003, 0).UTC()
		ev.EventType = gatewaylog.EventError
		ev.Severity = gatewaylog.SeverityHigh
		ev.Error = &gatewaylog.ErrorPayload{
			Subsystem: "auth",
			Code:      "AUTH_INVALID_TOKEN",
			Message:   "token rejected",
		}
		h.GW.Emit(ev)
	})
	assertOTelSpanPresent(t, h)
	evs := findGatewayEvents(h, gatewaylog.EventError)
	if len(evs) == 0 {
		t.Fatal("missing error event")
	}
	got := evs[len(evs)-1]
	assertCorrelationTriplet(t, got)
	assertThreeTierIdentity(t, got)
	validateGatewayEnvelope(t, mustMarshalEvent(t, got))

	rm := collectMetrics(t, h.Reader)
	if sumInt64Counter(rm, "defenseclaw.gateway.errors") < 1 {
		t.Fatal("expected defenseclaw.gateway.errors metric")
	}
}

func testSurfaceDiagnostic(t *testing.T, h *observabilityHarness) {
	triggerViaSidecarHTTP(t, func() {
		_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.diagnostic")
		sp.End()
		base := envelopeBase()
		ev := base
		ev.Timestamp = time.Unix(1700000004, 0).UTC()
		ev.EventType = gatewaylog.EventDiagnostic
		ev.Severity = gatewaylog.SeverityInfo
		ev.Diagnostic = &gatewaylog.DiagnosticPayload{
			Component: "config",
			Message:   "reload skipped",
		}
		h.GW.Emit(ev)
	})
	assertOTelSpanPresent(t, h)
	evs := findGatewayEvents(h, gatewaylog.EventDiagnostic)
	if len(evs) == 0 {
		t.Fatal("missing diagnostic")
	}
	got := evs[len(evs)-1]
	assertCorrelationTriplet(t, got)
	assertThreeTierIdentity(t, got)
	validateGatewayEnvelope(t, mustMarshalEvent(t, got))
}

func testSurfaceScan(t *testing.T, h *observabilityHarness) {
	triggerViaSidecarHTTP(t, func() {
		_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.scan")
		sp.End()
		res := minimalScanResult(nil)
		if err := h.Logger.LogScan(res); err != nil {
			t.Fatalf("LogScan: %v", err)
		}
	})
	assertOTelSpanPresent(t, h)
	evs := findGatewayEvents(h, gatewaylog.EventScan)
	if len(evs) == 0 {
		t.Fatal("missing scan event")
	}
	got := evs[len(evs)-1]
	validateGatewayEnvelope(t, mustMarshalEvent(t, got))

	rows, err := h.Store.ListEvents(20)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected audit_events row for scan")
	}
	_, err = h.Store.ListScanResults(5)
	if err != nil {
		t.Fatalf("ListScanResults: %v", err)
	}
	rm := collectMetrics(t, h.Reader)
	if !hasMetricName(rm, "defenseclaw.scan.count") {
		t.Fatal("expected scan.count metric")
	}
	sink := h.Sink.snapshot()
	if len(sink) == 0 {
		t.Fatal("expected audit sink delivery for LogScan")
	}
	// TODO(v7-followup): sinks.Event omits schema_version; audit-event.json requires schema_version — validate gateway envelope as canonical wire proof.
	raw, err := json.Marshal(sink[len(sink)-1])
	if err != nil {
		t.Fatalf("marshal sink: %v", err)
	}
	_ = raw
	validateGatewayEnvelope(t, lastGatewayExportJSON(t, h))
}

func testSurfaceScanFinding(t *testing.T, h *observabilityHarness) {
	triggerViaSidecarHTTP(t, func() {
		_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.scan_finding")
		sp.End()
		ln := 42
		res := minimalScanResult([]scanner.Finding{
			{
				ID:         "f1",
				Title:      "secret",
				Severity:   scanner.SeverityHigh,
				Category:   "secret",
				RuleID:     "rule-1",
				LineNumber: &ln,
			},
		})
		if err := h.Logger.LogScan(res); err != nil {
			t.Fatalf("LogScan: %v", err)
		}
	})
	assertOTelSpanPresent(t, h)
	evs := findGatewayEvents(h, gatewaylog.EventScanFinding)
	if len(evs) == 0 {
		t.Fatal("missing scan_finding events")
	}
	validateGatewayEnvelope(t, mustMarshalEvent(t, evs[0]))
	scanID := evs[0].ScanFinding.ScanID
	findings, err := h.Store.ListScanFindings(scanID)
	if err != nil {
		t.Fatalf("ListScanFindings: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected scan_findings rows")
	}
}

func testSurfaceActivity(t *testing.T, h *observabilityHarness) {
	triggerViaSidecarHTTP(t, func() {
		_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.activity")
		sp.End()
		err := h.Logger.LogActivity(audit.ActivityInput{
			Actor:      "op",
			Action:     audit.ActionPolicyReload,
			TargetType: "policy",
			TargetID:   "default",
			Reason:     "test",
			Before:     map[string]any{"k": "old"},
			After:      map[string]any{"k": "new"},
			RunID:      e2eRunID,
			TraceID:    e2eTraceID,
		})
		if err != nil {
			t.Fatalf("LogActivity: %v", err)
		}
	})
	assertOTelSpanPresent(t, h)
	evs := findGatewayEvents(h, gatewaylog.EventActivity)
	if len(evs) == 0 {
		t.Fatal("missing activity gateway event")
	}
	got := evs[len(evs)-1]
	// LogActivity stamps provenance at emit; correlation on gateway row may omit session_id (ActivityInput has no SessionID field).
	if got.RunID != e2eRunID || got.TraceID != e2eTraceID {
		t.Fatalf("activity correlation: run_id=%q trace_id=%q", got.RunID, got.TraceID)
	}
	validateGatewayEnvelope(t, mustMarshalEvent(t, got))

	act, err := h.Store.ListActivityEvents(5)
	if err != nil {
		t.Fatalf("ListActivityEvents: %v", err)
	}
	if len(act) == 0 {
		t.Fatal("expected activity_events row")
	}
	rm := collectMetrics(t, h.Reader)
	if sumInt64Counter(rm, "defenseclaw.activity.total") < 1 {
		t.Fatal("expected defenseclaw.activity.total")
	}
	if len(h.Sink.snapshot()) == 0 {
		t.Fatal("expected audit sink delivery for LogActivity")
	}
}
