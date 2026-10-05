// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// TestOpenClawBlockLandsOnTheToolSpan pins GAP-1930: the decision the
// inspect endpoint made for an OpenClaw tool call is on the tool span the
// event router emits for it, with the rule, severity and user, as on the
// hook connectors' tool spans. It was only on a separate apply_guardrail
// trace, which never reached Galileo.
func TestOpenClawBlockLandsOnTheToolSpan(t *testing.T) {
	now := time.Date(2026, 10, 2, 21, 59, 6, 0, time.UTC)
	openClawToolOutcomes.mu.Lock()
	openClawToolOutcomes.entries, openClawToolOutcomes.now = nil, func() time.Time { return now }
	openClawToolOutcomes.mu.Unlock()
	t.Cleanup(func() {
		openClawToolOutcomes.mu.Lock()
		openClawToolOutcomes.entries, openClawToolOutcomes.now = nil, nil
		openClawToolOutcomes.mu.Unlock()
	})

	outcome, ok := hookGuardrailOutcomeFor("block", "CRITICAL", "matched: MR1-MARKER-BLOCK:marker", []string{"MR1-MARKER-BLOCK"})
	if !ok {
		t.Fatal("no outcome for a block")
	}
	user := AgentIdentity{UserID: "501", UserIDKind: "posix_uid", UserName: "dcm-std1"}
	marker := []byte(`{"command":"echo dcmr1-block-marker > /tmp/dcmc4-openclaw.txt"}`)
	rememberOpenClawToolOutcome("sess-uuid", "run-2", "exec", []byte(`{"command":"echo two"}`), outcome, user)
	rememberOpenClawToolOutcome("sess-uuid", "run-1", "exec", marker, outcome, user)

	// A call with another command never takes the decision.
	other := generatedToolV8Observation{
		tool: "exec", arguments: `{"command":"ls"}`,
		meta: llmEventMeta{Source: "openclaw", SessionID: "agent:main:main", RunID: "run-9"},
	}
	applyOpenClawToolOutcome(&other)
	if other.meta.Guardrail.Action != "" {
		t.Fatalf("another command took the decision: %+v", other.meta.Guardrail)
	}
	write := generatedToolV8Observation{tool: "write", meta: llmEventMeta{Source: "openclaw", RunID: "run-1"}}
	applyOpenClawToolOutcome(&write)
	if write.meta.Guardrail.Action != "" {
		t.Fatalf("another tool took the decision: %+v", write.meta.Guardrail)
	}

	// GAP-1930 r4: live, the stream names its own run id and the session
	// key, so neither id matches the plugin's; the arguments do (formatted
	// differently, with a field the plugin did not send).
	observation := generatedToolV8Observation{
		tool: "exec", startedAt: now, finishedAt: now.Add(time.Second),
		arguments: `{"command": "echo dcmr1-block-marker \u003e /tmp/dcmc4-openclaw.txt", "timeout": 30}`,
		meta:      llmEventMeta{Source: "openclaw", SessionID: "agent:main:tui-9b76", RunID: "run-stream", ToolID: "call_1"},
	}
	applyOpenClawToolOutcome(&observation)
	input := generatedToolV8Input(observation)
	if action, _ := input.DefenseClawGuardrailAction.Get(); action != "block" {
		t.Fatalf("guardrail action = %v", input.DefenseClawGuardrailAction)
	}
	if rule, _ := input.DefenseClawGuardrailRuleID.Get(); rule != "MR1-MARKER-BLOCK" {
		t.Fatalf("rule = %v", input.DefenseClawGuardrailRuleID)
	}
	if severity, _ := input.DefenseClawGuardrailSeverity.Get(); severity != "CRITICAL" {
		t.Fatalf("severity = %v", input.DefenseClawGuardrailSeverity)
	}
	if name, _ := input.DefenseClawUserName.Get(); name != "dcm-std1" {
		t.Fatalf("user = %v", input.DefenseClawUserName)
	}
	if input.Outcome != observability.OutcomeBlocked {
		t.Fatalf("outcome = %v", input.Outcome)
	}
	// Taken once: the same command again does not find it.
	again := generatedToolV8Observation{tool: "exec", arguments: string(marker), meta: llmEventMeta{Source: "openclaw", RunID: "run-1"}}
	applyOpenClawToolOutcome(&again)
	if again.meta.Guardrail.Action != "" {
		t.Fatalf("decision taken twice: %+v", again.meta.Guardrail)
	}

	// Expired decisions are dropped.
	now = now.Add(openClawToolOutcomeTTL)
	late := generatedToolV8Observation{tool: "exec", meta: llmEventMeta{Source: "openclaw", RunID: "run-2"}}
	applyOpenClawToolOutcome(&late)
	if late.meta.Guardrail.Action != "" {
		t.Fatalf("expired decision taken: %+v", late.meta.Guardrail)
	}
}

// TestOpenClawAllowedToolSpanNamesTheLocalUser pins GAP-2358: an allowed
// OpenClaw tool call (no remembered decision) names the gateway's own user
// on an unmanaged install, as the blocked call and the turn's agent and chat
// spans do; a user the stream named is kept.
func TestOpenClawAllowedToolSpanNamesTheLocalUser(t *testing.T) {
	_, wantName := localProcessUser()
	if wantName == "" {
		t.Skip("no local process user on this host")
	}
	allowed := generatedToolV8Observation{tool: "write", meta: llmEventMeta{Source: "openclaw", RunID: "run-allowed-2358"}}
	applyOpenClawToolOutcome(&allowed)
	if allowed.meta.Guardrail.Action != "" {
		t.Fatalf("an allowed call took a decision: %+v", allowed.meta.Guardrail)
	}
	if allowed.meta.UserName != wantName {
		t.Fatalf("allowed tool span user = %q, want %q", allowed.meta.UserName, wantName)
	}
	named := generatedToolV8Observation{tool: "exec", meta: llmEventMeta{Source: "openclaw", UserName: "stream-user"}}
	applyOpenClawToolOutcome(&named)
	if named.meta.UserName != "stream-user" {
		t.Fatalf("stream user replaced by %q", named.meta.UserName)
	}
}
