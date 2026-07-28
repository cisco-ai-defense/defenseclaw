// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func countStoredCanonicalEventsV8(t *testing.T, path string, eventName string, mandatory bool) int {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mandatoryValue := 0
	if mandatory {
		mandatoryValue = 1
	}
	var count int
	if err := database.QueryRow(
		"SELECT COUNT(*) FROM audit_events WHERE event_name = ? AND mandatory = ?",
		eventName, mandatoryValue,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAPIPolicyEvaluationV8EmitsCorrelatedLogSpanAndMetrics(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	api := &APIServer{
		health: NewSidecarHealth(), store: capture.store, logger: audit.NewLogger(capture.store),
	}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	ctx, parent := platformHealthCorrelatedContext(t)
	_, operation, err := api.startAPIPolicyEvaluationV8(ctx, "admission", "skill", "private/skill")
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.complete("blocked", "policy matched", "HIGH", nil); err != nil {
		t.Fatal(err)
	}

	rows := readStoredGuardrailEventsV8(t, capture.store.DatabasePath())
	if len(rows) != 1 {
		t.Fatalf("generated policy rows=%+v", rows)
	}
	row := rows[0]
	if row.Body["defenseclaw.guardrail.name"] != "opa-admission" ||
		row.Body["defenseclaw.guardrail.target_type"] != "skill" ||
		row.Body["defenseclaw.guardrail.target_ref"] != "private/skill" ||
		row.Body["defenseclaw.guardrail.effective_action"] != "blocked" ||
		row.Body["defenseclaw.security.severity"] != "HIGH" ||
		row.Correlation.TraceID != parent.TraceID().String() ||
		row.Correlation.RequestID != "request-platform" ||
		row.Correlation.SessionID != "session-platform" ||
		row.Correlation.TurnID != "turn-platform" ||
		row.Correlation.AgentID != "agent-platform" ||
		row.Correlation.PolicyID != "policy-platform" ||
		row.Correlation.ToolInvocationID != "tool-platform" ||
		row.Correlation.EvaluationID == "" {
		t.Fatalf("generated policy row=%+v", row)
	}

	spans := proxyGeneratedSpansForFamily(capture.snapshot(), observability.TelemetryFamilyGuardrailApply)
	if len(spans) != 1 {
		t.Fatalf("generated policy spans=%d", len(spans))
	}
	spanParent, hasParent := spans[0].ParentSpanID()
	if spans[0].TraceID() != parent.TraceID() || !hasParent || spanParent != parent.SpanID() {
		t.Fatalf("generated policy span trace=%s parent=%s/%t", spans[0].TraceID(), spanParent, hasParent)
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawPolicyEvaluations,
		observability.TelemetryInstrumentDefenseClawPolicyLatency,
		observability.TelemetryInstrumentDefenseClawAdmissionDecisions,
		observability.TelemetryInstrumentDefenseClawSloBlockLatency,
	} {
		metrics := generatedMetricByName(capture.metricSnapshot(), name)
		if len(metrics) != 1 {
			t.Fatalf("generated policy metric %s count=%d snapshot=%v", name, len(metrics), capture.metricSnapshot())
		}
		if correlation := metrics[0].CanonicalRecord().Correlation(); correlation.TraceID != parent.TraceID().String() || correlation.EvaluationID != row.Correlation.EvaluationID {
			t.Fatalf("generated policy metric %s correlation=%+v", name, correlation)
		}
	}
}

func TestAPIPolicyEvaluationV8KeepsLogAndMetricsWhenTraceSamplingIsOff(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntimeWithSampler(t, "always_off")
	api := &APIServer{
		health: NewSidecarHealth(), store: capture.store, logger: audit.NewLogger(capture.store),
	}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	_, operation, err := api.startAPIPolicyEvaluationV8(t.Context(), "audit", "audit-event", "retention/check")
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.complete("retain", "retention policy matched", "", nil); err != nil {
		t.Fatal(err)
	}
	if spans := capture.snapshot(); len(spans) != 0 {
		t.Fatalf("unsampled policy spans=%d", len(spans))
	}
	rows := readStoredGuardrailEventsV8(t, capture.store.DatabasePath())
	if len(rows) != 1 {
		t.Fatalf("unsampled policy rows=%+v", rows)
	}
	if _, fabricated := rows[0].Body["defenseclaw.security.severity"]; fabricated {
		t.Fatalf("policy evaluation fabricated severity: %v", rows[0].Body)
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawPolicyEvaluations,
		observability.TelemetryInstrumentDefenseClawPolicyLatency,
	} {
		if metrics := generatedMetricByName(capture.metricSnapshot(), name); len(metrics) != 1 {
			t.Fatalf("unsampled policy metric %s count=%d", name, len(metrics))
		}
	}
}

func TestAPIPolicyEvaluationV8RequiresRuntimeWithoutPersistence(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{health: NewSidecarHealth(), store: store, logger: logger}
	if _, operation, err := api.startAPIPolicyEvaluationV8(t.Context(), "admission", "skill", "example"); err == nil || operation != nil {
		t.Fatalf("unbound policy operation=%v err=%v", operation, err)
	}
	if events, err := store.ListEvents(10); err != nil || len(events) != 0 {
		t.Fatalf("unbound policy persisted events=%+v err=%v", events, err)
	}
}

func TestAPIPolicyEvaluationV8TechnicalFailureDoesNotInventDecision(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	api := &APIServer{
		health: NewSidecarHealth(), store: capture.store, logger: audit.NewLogger(capture.store),
	}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	_, operation, err := api.startAPIPolicyEvaluationV8(t.Context(), "firewall", "network", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.complete("", "", "", errors.New("policy engine unavailable")); err != nil {
		t.Fatal(err)
	}
	if count := countStoredCanonicalEventsV8(
		t, capture.store.DatabasePath(), observability.TelemetryEventGuardrailEvaluationFailed, false,
	); count != 1 {
		t.Fatalf("generated failed policy events=%d", count)
	}
	spans := proxyGeneratedSpansForFamily(capture.snapshot(), observability.TelemetryFamilyGuardrailApply)
	if len(spans) != 1 {
		t.Fatalf("generated failed policy spans=%d", len(spans))
	}
	attributes := proxyCanonicalAttributes(t, spans[0].Record())
	if attributes["error.type"] != "policy_evaluation_failed" {
		t.Fatalf("generated failed policy attributes=%v", attributes)
	}
	for _, key := range []string{"defenseclaw.guardrail.decision", "defenseclaw.guardrail.effective_action"} {
		if _, fabricated := attributes[key]; fabricated {
			t.Fatalf("technical failure fabricated %s: %v", key, attributes)
		}
	}
	metrics := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawPolicyEvaluations)
	if len(metrics) != 1 || metrics[0].Attributes()["defenseclaw.metric.policy.verdict"] != "error" {
		t.Fatalf("generated failed policy metrics=%v", metrics)
	}
}

func TestAPIPolicyReloadRejectedUsesMandatoryFloorWhenLogsAreDisabled(t *testing.T) {
	disabled := false
	runtime, capture := newProxyGeneratedTraceRuntimeWithSamplerAndDefaults(
		t, "always_off", config.ObservabilityV8BucketPolicySource{
			Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
		},
	)
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	if err := api.emitAPIPolicyReloadRejectedV8(t.Context(), "compile failed"); err != nil {
		t.Fatal(err)
	}
	if count := countStoredCanonicalEventsV8(
		t, capture.store.DatabasePath(), observability.TelemetryEventPolicyReloadRejected, true,
	); count != 1 {
		t.Fatalf("mandatory policy reload rejection events=%d", count)
	}
}
