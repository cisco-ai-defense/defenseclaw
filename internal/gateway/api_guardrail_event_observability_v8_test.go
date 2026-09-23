// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type storedGuardrailEventV8 struct {
	Action      string
	Mandatory   int
	Body        map[string]any
	Correlation observability.Correlation
}

func TestACPEvaluationEmitsGuardrailV8Attributes(t *testing.T) {
	api, capture := newGuardrailEventV8TestAPI(t)
	api.recordACPEvaluationV8(t.Context(), acp.Evaluation{
		ClientID: "zed", AgentID: "kiro", Profile: "kiro-only",
		Method: "session/prompt", Direction: acp.ClientToAgent, Surface: acp.SurfacePrompt,
	}, acp.Verdict{Action: "allow", RawAction: "block", WouldBlock: true, Severity: "HIGH", Reason: "test policy"},
		nil, "kiro", "kiro-only", 12*time.Millisecond)

	events := readStoredGuardrailEventsV8(t, capture.store.DatabasePath())
	if len(events) != 1 {
		t.Fatalf("stored events = %d, want 1", len(events))
	}
	want := map[string]any{
		"defenseclaw.acp.client": "zed", "defenseclaw.acp.agent": "kiro",
		"defenseclaw.acp.method": "session/prompt", "defenseclaw.acp.direction": "client_to_agent",
		"defenseclaw.acp.surface": "prompt", "defenseclaw.acp.profile": "kiro-only",
		"defenseclaw.acp.protocol.version": acp.SchemaVersion,
		"defenseclaw.guardrail.raw_action": "block", "defenseclaw.guardrail.would_block": true,
		"defenseclaw.guardrail.effective_action": "allow",
	}
	for key, value := range want {
		if got := events[0].Body[key]; got != value {
			t.Errorf("%s = %#v, want %#v (body=%v)", key, got, value, events[0].Body)
		}
	}
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

// rule_ids and finding_count are both derived from the request's Findings, so
// an ACP evaluation that omitted them published every block as "no findings"
// while its reason named the rule that matched. A SIEM rolling up either
// attribute saw zero ACP findings even though the hook lane reported them for
// identical content.
func TestACPEvaluationPublishesMatchedFindings(t *testing.T) {
	api, capture := newGuardrailEventV8TestAPI(t)
	api.recordACPEvaluationV8(t.Context(), acp.Evaluation{
		ClientID: "zed", AgentID: "kiro", Profile: "kiro-only",
		Method: "session/prompt", Direction: acp.ClientToAgent, Surface: acp.SurfacePrompt,
	}, acp.Verdict{
		Action: "block", RawAction: "block", Severity: "CRITICAL",
		Reason: "matched: TRUST-IGNORE-PREVIOUS:Ignore previous instructions",
	}, []string{
		"TRUST-IGNORE-PREVIOUS:Ignore previous instructions",
		"TRUST-JAILBREAK:Jailbreak attempt",
	}, "kiro", "kiro-only", 3*time.Millisecond)

	events := readStoredGuardrailEventsV8(t, capture.store.DatabasePath())
	if len(events) != 1 {
		t.Fatalf("stored events = %d, want 1", len(events))
	}
	body := events[0].Body
	if count, _ := body["defenseclaw.guardrail.finding_count"].(float64); int(count) != 2 {
		t.Errorf("finding_count = %#v, want 2 (body=%v)", body["defenseclaw.guardrail.finding_count"], body)
	}
	raw, ok := body["defenseclaw.guardrail.rule_ids"]
	if !ok {
		t.Fatalf("rule_ids is absent; a named reason without rule ids is unqueryable (body=%v)", body)
	}
	rendered := fmt.Sprint(raw)
	for _, want := range []string{"TRUST-IGNORE-PREVIOUS", "TRUST-JAILBREAK"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rule_ids %v is missing %q", raw, want)
		}
	}
}

// A profile-denied method is a policy veto, not a scanner match. It must not
// invent a finding to justify itself.
func TestACPDeniedMethodPublishesNoFindings(t *testing.T) {
	api, capture := newGuardrailEventV8TestAPI(t)
	api.recordACPEvaluationV8(t.Context(), acp.Evaluation{
		ClientID: "zed", AgentID: "kiro", Profile: "kiro-only",
		Method: "fs/write_text_file", Direction: acp.ClientToAgent, Surface: acp.SurfaceFilesystem,
	}, acp.Verdict{
		Action: "block", RawAction: "block", Severity: "HIGH",
		Reason: "method denied by ACP profile",
	}, nil, "kiro", "kiro-only", time.Millisecond)

	events := readStoredGuardrailEventsV8(t, capture.store.DatabasePath())
	if len(events) != 1 {
		t.Fatalf("stored events = %d, want 1", len(events))
	}
	if count, _ := events[0].Body["defenseclaw.guardrail.finding_count"].(float64); int(count) != 0 {
		t.Errorf("finding_count = %#v, want 0", events[0].Body["defenseclaw.guardrail.finding_count"])
	}
}
