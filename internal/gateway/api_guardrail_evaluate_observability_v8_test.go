// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

func TestNewAPIGuardrailEvaluateV8RequestFactsRejectsInvalidSourceFacts(t *testing.T) {
	valid := guardrailEvaluateRequest{
		EvaluationID: "eval-1", Direction: "prompt", Mode: "action", ScannerMode: "local",
	}
	tests := []struct {
		name   string
		mutate func(*guardrailEvaluateRequest)
	}{
		{name: "evaluation id", mutate: func(value *guardrailEvaluateRequest) { value.EvaluationID = "bad id" }},
		{name: "direction", mutate: func(value *guardrailEvaluateRequest) { value.Direction = "pre_call" }},
		{name: "mode", mutate: func(value *guardrailEvaluateRequest) { value.Mode = "blocking" }},
		{name: "scanner mode", mutate: func(value *guardrailEvaluateRequest) { value.ScannerMode = "cloud" }},
		{name: "content length", mutate: func(value *guardrailEvaluateRequest) { value.ContentLength = -1 }},
		{name: "elapsed", mutate: func(value *guardrailEvaluateRequest) { value.ElapsedMs = -1 }},
		{name: "model", mutate: func(value *guardrailEvaluateRequest) { value.Model = "bad model" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := newAPIGuardrailEvaluateV8RequestFacts(t.Context(), nil, request); err == nil {
				t.Fatalf("invalid guardrail evaluate request accepted: %+v", request)
			}
		})
	}
}

func TestAPIGuardrailEvaluateV8CompletionRejectsInvalidPolicyOutput(t *testing.T) {
	facts, err := newAPIGuardrailEvaluateV8RequestFacts(t.Context(), nil, guardrailEvaluateRequest{
		EvaluationID: "eval-output", Direction: "prompt", Mode: "action",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		output *policy.GuardrailOutput
	}{
		{name: "nil", output: nil},
		{name: "action", output: &policy.GuardrailOutput{Action: "maybe", Severity: "HIGH"}},
		{name: "severity", output: &policy.GuardrailOutput{Action: "allow", Severity: "WARN"}},
		{name: "source", output: &policy.GuardrailOutput{Action: "allow", Severity: "NONE", ScannerSources: []string{"bad source"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := facts.complete(test.output, time.Unix(1, 0), time.Unix(1, 1)); err == nil {
				t.Fatalf("invalid guardrail output accepted: %+v", test.output)
			}
		})
	}
}

func TestHandleGuardrailEvaluateEmitsOneRichCorrelatedV8Evaluation(t *testing.T) {
	api, capture := newGuardrailEventV8TestAPI(t)
	ctx, parent := platformHealthCorrelatedContext(t)
	body, err := json.Marshal(guardrailEvaluateRequest{
		EvaluationID: "eval-rich-opa", Direction: "prompt", Model: "gpt-4",
		Mode: "action", ScannerMode: "both", ContentLength: 512, ElapsedMs: 7.25,
		LocalResult: &policy.GuardrailScanResult{
			Action: "alert", Severity: "MEDIUM", Findings: []string{"SEC-LOCAL:credential"},
		},
		CiscoResult: &policy.GuardrailScanResult{
			Action: "block", Severity: "HIGH", Findings: []string{"SEC-CISCO:prompt injection"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/guardrail/evaluate", bytes.NewReader(body)).WithContext(ctx)
	response := httptest.NewRecorder()

	api.handleGuardrailEvaluate(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	rows := readStoredGuardrailEventsV8(t, capture.store.DatabasePath())
	if len(rows) != 1 {
		t.Fatalf("generated OPA guardrail rows=%+v", rows)
	}
	row := rows[0]
	sources, ok := row.Body["defenseclaw.guardrail.detector.sources"].([]any)
	rules, rulesOK := row.Body["defenseclaw.guardrail.rule_ids"].([]any)
	if row.Action != "guardrail-opa-verdict" ||
		row.Body["defenseclaw.evaluation.id"] != "eval-rich-opa" ||
		row.Body["gen_ai.request.model"] != "gpt-4" ||
		row.Body["defenseclaw.guardrail.mode"] != "enforce" ||
		row.Body["defenseclaw.guardrail.effective_action"] != "alert" ||
		row.Body["defenseclaw.guardrail.reason"] != "built-in fallback (no policy configured)" ||
		row.Body["defenseclaw.guardrail.finding_count"] != float64(2) ||
		row.Body["defenseclaw.guardrail.detector.name"] != "opa-guardrail" ||
		!ok || len(sources) != 1 || sources[0] != "scanner" ||
		!rulesOK || len(rules) != 2 || rules[0] != "SEC-LOCAL" || rules[1] != "SEC-CISCO" {
		t.Fatalf("generated OPA guardrail row=%+v", row)
	}
	if _, fabricated := row.Body["defenseclaw.guardrail.enforced"]; fabricated {
		t.Fatalf("OPA evaluation fabricated enforcement: %v", row.Body)
	}
	if _, fabricated := row.Body["defenseclaw.guardrail.would_block"]; fabricated {
		t.Fatalf("OPA evaluation fabricated would_block: %v", row.Body)
	}
	if row.Correlation.TraceID != parent.TraceID().String() ||
		row.Correlation.RequestID != "request-platform" ||
		row.Correlation.SessionID != "session-platform" ||
		row.Correlation.TurnID != "turn-platform" ||
		row.Correlation.AgentID != "agent-platform" ||
		row.Correlation.PolicyID != "policy-platform" ||
		row.Correlation.ToolInvocationID != "tool-platform" ||
		row.Correlation.ConnectorID != "codex" ||
		row.Correlation.EvaluationID != "eval-rich-opa" {
		t.Fatalf("generated OPA guardrail correlation=%+v", row.Correlation)
	}

	metrics := capture.metricSnapshot()
	evaluations := generatedMetricByName(metrics, observability.TelemetryInstrumentDefenseClawGuardrailEvaluations)
	latencies := generatedMetricByName(metrics, observability.TelemetryInstrumentDefenseClawGuardrailLatency)
	if len(evaluations) != 1 || len(latencies) != 1 {
		t.Fatalf("generated OPA metric counts=%d/%d", len(evaluations), len(latencies))
	}
	for _, metric := range append(evaluations, latencies...) {
		if metric.Attributes()["defenseclaw.metric.guardrail.scanner"] != "opa-guardrail" ||
			metric.CanonicalRecord().Correlation().EvaluationID != "eval-rich-opa" ||
			metric.CanonicalRecord().Correlation().TraceID != parent.TraceID().String() {
			t.Fatalf("generated OPA metric %s=%v correlation=%+v",
				metric.Descriptor().Name, metric.Attributes(), metric.CanonicalRecord().Correlation())
		}
	}

	spans := proxyGeneratedSpansForFamily(capture.snapshot(), observability.TelemetryFamilyGuardrailApply)
	if len(spans) != 1 {
		t.Fatalf("generated OPA guardrail spans=%d", len(spans))
	}
	span := spans[0]
	attributes := proxyCanonicalAttributes(t, span.Record())
	spanParent, hasParent := span.ParentSpanID()
	if span.TraceID() != parent.TraceID() || !hasParent || spanParent != parent.SpanID() ||
		attributes["defenseclaw.evaluation.id"] != "eval-rich-opa" ||
		attributes["defenseclaw.guardrail.phase"] != "policy" ||
		attributes["defenseclaw.guardrail.detector.name"] != "opa-guardrail" ||
		attributes["defenseclaw.guardrail.mode"] != "enforce" {
		t.Fatalf("generated OPA span parent=%s/%t record=%v", spanParent, hasParent, attributes)
	}
}

func TestHandleGuardrailEvaluateKeepsLogsAndMetricsWhenTraceSamplingIsOff(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntimeWithSampler(t, "always_off")
	api := &APIServer{
		health: NewSidecarHealth(), store: capture.store, logger: audit.NewLogger(capture.store),
	}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	body, err := json.Marshal(guardrailEvaluateRequest{
		EvaluationID: "eval-unsampled", Direction: "completion", Mode: "observe",
		LocalResult: &policy.GuardrailScanResult{Action: "allow", Severity: "NONE"},
		ElapsedMs:   1.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/guardrail/evaluate", bytes.NewReader(body))
	response := httptest.NewRecorder()

	api.handleGuardrailEvaluate(response, request)

	if response.Code != http.StatusOK || len(capture.snapshot()) != 0 {
		t.Fatalf("unsampled status=%d spans=%d body=%s", response.Code, len(capture.snapshot()), response.Body.String())
	}
	if rows := readStoredGuardrailEventsV8(t, capture.store.DatabasePath()); len(rows) != 1 {
		t.Fatalf("unsampled generated rows=%+v", rows)
	}
	if metrics := capture.metricSnapshot(); len(generatedMetricByName(metrics, observability.TelemetryInstrumentDefenseClawGuardrailEvaluations)) != 1 ||
		len(generatedMetricByName(metrics, observability.TelemetryInstrumentDefenseClawGuardrailLatency)) != 1 {
		t.Fatalf("unsampled generated metrics=%v", metrics)
	}
}

func TestHandleGuardrailEvaluateRequiresV8RuntimeWithoutPersistence(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{health: NewSidecarHealth(), store: store, logger: logger}
	body, err := json.Marshal(guardrailEvaluateRequest{
		EvaluationID: "eval-unbound", Direction: "prompt", Mode: "action",
		LocalResult: &policy.GuardrailScanResult{Action: "allow", Severity: "NONE"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/guardrail/evaluate", bytes.NewReader(body))
	response := httptest.NewRecorder()

	api.handleGuardrailEvaluate(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unbound status=%d body=%s", response.Code, response.Body.String())
	}
	if events, err := store.ListEvents(10); err != nil || len(events) != 0 {
		t.Fatalf("unbound persisted events=%+v err=%v", events, err)
	}
}
