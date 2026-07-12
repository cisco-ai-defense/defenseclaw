// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type storedGuardrailEventV8 struct {
	Action      string
	Mandatory   int
	Body        map[string]any
	Correlation observability.Correlation
}

func newGuardrailEventV8TestAPI(
	t *testing.T,
) (*APIServer, *proxyCanonicalCapture) {
	t.Helper()
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	api := &APIServer{
		health: NewSidecarHealth(), store: capture.store, logger: audit.NewLogger(capture.store),
	}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	return api, capture
}

func readStoredGuardrailEventsV8(t *testing.T, path string) []storedGuardrailEventV8 {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT action, mandatory, projected_record_json FROM audit_events
		WHERE event_name = 'guardrail.evaluation.completed' ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []storedGuardrailEventV8
	for rows.Next() {
		var item storedGuardrailEventV8
		var raw string
		if err := rows.Scan(&item.Action, &item.Mandatory, &raw); err != nil {
			t.Fatal(err)
		}
		var projected struct {
			Body        map[string]any            `json:"body"`
			Correlation observability.Correlation `json:"correlation"`
		}
		if err := json.Unmarshal([]byte(raw), &projected); err != nil {
			t.Fatal(err)
		}
		item.Body, item.Correlation = projected.Body, projected.Correlation
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNewAPIGuardrailEventV8FactsRejectsInvalidSourceFacts(t *testing.T) {
	negativeTokens := int64(-1)
	tests := []struct {
		name    string
		request guardrailEventRequest
	}{
		{name: "evaluation id", request: guardrailEventRequest{EvaluationID: "bad id", Direction: "prompt", Action: "allow", Severity: "NONE"}},
		{name: "direction", request: guardrailEventRequest{EvaluationID: "eval-1", Direction: "pre_call", Action: "allow", Severity: "NONE"}},
		{name: "action", request: guardrailEventRequest{EvaluationID: "eval-1", Direction: "prompt", Action: "allowed", Severity: "NONE"}},
		{name: "severity", request: guardrailEventRequest{EvaluationID: "eval-1", Direction: "prompt", Action: "allow", Severity: "WARN"}},
		{name: "latency", request: guardrailEventRequest{EvaluationID: "eval-1", Direction: "prompt", Action: "allow", Severity: "NONE", ElapsedMs: -1}},
		{name: "tokens", request: guardrailEventRequest{EvaluationID: "eval-1", Direction: "prompt", Action: "allow", Severity: "NONE", TokensIn: &negativeTokens}},
		{name: "model", request: guardrailEventRequest{EvaluationID: "eval-1", Direction: "prompt", Action: "allow", Severity: "NONE", Model: "bad model"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newAPIGuardrailEventV8Facts(t.Context(), "codex", test.request); err == nil {
				t.Fatalf("invalid guardrail event facts accepted: %+v", test.request)
			}
		})
	}
}
