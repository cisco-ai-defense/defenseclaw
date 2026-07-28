// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"fmt"
	"testing"
)

func TestGeneratedHookDecisionPreservesFinalConnectorFactsWithoutEvaluation(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	record, err := builder.BuildLogCompatHookDecision(LogCompatHookDecisionInput{
		Envelope:                            testFamilyEnvelope(),
		Outcome:                             OutcomeAllowed,
		DefenseClawRequestID:                Present("request-1"),
		DefenseClawTurnID:                   Present("turn-1"),
		DefenseClawAgentLineageProvenance:   Present("reported"),
		DefenseClawHookEvent:                "PreToolUse",
		DefenseClawHookResult:               "ok",
		DefenseClawGuardrailEffectiveAction: "allow",
		DefenseClawGuardrailRawAction:       "allow",
		DefenseClawSecuritySeverity:         "INFO",
		DefenseClawGuardrailMode:            "enforce",
		DefenseClawGuardrailWouldBlock:      false,
		DefenseClawGuardrailEnforced:        false,
		DefenseClawConnectorStepIdx:         Present[int64](1),
		DefenseClawGuardrailLatencyMs:       Present(2.5),
		DefenseClawGuardrailRuleIds:         Present([]string{"rule-1"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	body := generatedContractBody(t, record)
	want := map[string]any{
		"defenseclaw.request.id":                 "request-1",
		"defenseclaw.turn.id":                    "turn-1",
		"defenseclaw.agent.lineage.provenance":   "reported",
		"defenseclaw.hook.event":                 "PreToolUse",
		"defenseclaw.hook.result":                "ok",
		"defenseclaw.guardrail.effective_action": "allow",
		"defenseclaw.guardrail.raw_action":       "allow",
		"defenseclaw.security.severity":          "INFO",
		"defenseclaw.guardrail.mode":             "enforce",
		"defenseclaw.guardrail.would_block":      false,
		"defenseclaw.guardrail.enforced":         false,
	}
	for key, expected := range want {
		if actual := body[key]; actual != expected {
			t.Errorf("%s=%v (%T), want %v (%T)", key, actual, actual, expected, expected)
		}
	}
	if _, fabricated := body["defenseclaw.evaluation.id"]; fabricated {
		t.Fatal("clean hook decision fabricated an evaluation ID")
	}
	if fmt.Sprint(body["defenseclaw.connector.step_idx"]) != "1" ||
		fmt.Sprint(body["defenseclaw.guardrail.latency_ms"]) != "2.5" {
		t.Fatalf("step/latency=%v/%v", body["defenseclaw.connector.step_idx"], body["defenseclaw.guardrail.latency_ms"])
	}
	rules, ok := body["defenseclaw.guardrail.rule_ids"].([]any)
	if !ok || len(rules) != 1 || rules[0] != "rule-1" {
		t.Fatalf("rule IDs=%v", body["defenseclaw.guardrail.rule_ids"])
	}
}

func TestGeneratedHookDecisionRejectsInvalidTechnicalResultAndStep(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	valid := LogCompatHookDecisionInput{
		Envelope: testFamilyEnvelope(), Outcome: OutcomeAllowed,
		DefenseClawHookEvent: "PreToolUse", DefenseClawHookResult: "ok",
		DefenseClawGuardrailEffectiveAction: "allow", DefenseClawGuardrailRawAction: "allow",
		DefenseClawSecuritySeverity: "INFO", DefenseClawGuardrailMode: "observe",
	}

	invalidResult := valid
	invalidResult.DefenseClawHookResult = "success"
	if _, err := builder.BuildLogCompatHookDecision(invalidResult); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("invalid hook result error=%v", err)
	}
	invalidStep := valid
	invalidStep.DefenseClawConnectorStepIdx = Present[int64](0)
	if _, err := builder.BuildLogCompatHookDecision(invalidStep); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("zero connector step error=%v", err)
	}
}

func TestGeneratedLifecycleLogPreservesInteractionModelToolCostAndLineage(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	record, err := builder.BuildLogCompatSessionStart(LogCompatSessionStartInput{
		Envelope: testFamilyEnvelope(), Outcome: OutcomeAttempted,
		GenAIConversationID: "conversation-1", GenAIAgentID: "agent-1",
		DefenseClawAgentRootID: "agent-1", DefenseClawSessionRootID: "conversation-1",
		DefenseClawAgentLifecycleID: "lifecycle-1", DefenseClawAgentExecutionID: "execution-1",
		DefenseClawAgentDepth: 0, DefenseClawAgentLifecycleEvent: "session_start",
		DefenseClawAgentLifecycleState:    "active",
		DefenseClawAgentLineageProvenance: Present("reported"),
		DefenseClawRequestID:              Present("request-1"), DefenseClawTurnID: Present("turn-1"),
		DefenseClawOperationID: Present("operation-1"), DefenseClawRunID: Present("run-1"),
		UserID: Present("user-1"), DefenseClawPolicyID: Present("policy-1"),
		DefenseClawPolicyVersion: Present("policy-v1"), DefenseClawDestinationApp: Present("terminal"),
		GenAIProviderName: Present("openai"), GenAIRequestModel: Present("gpt-5"),
		GenAIResponseModel: Present("gpt-5-2026-07-01"), GenAIResponseID: Present("response-1"),
		DefenseClawModelRequestID:  Present("model-request-1"),
		DefenseClawModelResponseID: Present("model-response-1"),
		DefenseClawToolID:          Present("tool-1"), GenAIToolName: Present("shell"),
		GenAIToolType: Present("function"), GenAIToolCallID: Present("tool-call-1"),
		DefenseClawToolProvider: Present("builtin"), DefenseClawToolSkillKey: Present("shell.exec"),
		DefenseClawAgentReportedCostPresent: true,
		DefenseClawAgentReportedCostUsd:     Present(0.25),
	})
	if err != nil {
		t.Fatal(err)
	}
	body := generatedContractBody(t, record)
	want := map[string]any{
		"defenseclaw.agent.lineage.provenance":    "reported",
		"defenseclaw.request.id":                  "request-1",
		"defenseclaw.turn.id":                     "turn-1",
		"defenseclaw.operation.id":                "operation-1",
		"defenseclaw.run.id":                      "run-1",
		"user.id":                                 "user-1",
		"defenseclaw.policy.id":                   "policy-1",
		"defenseclaw.destination.app":             "terminal",
		"gen_ai.provider.name":                    "openai",
		"gen_ai.request.model":                    "gpt-5",
		"gen_ai.response.id":                      "response-1",
		"gen_ai.tool.name":                        "shell",
		"gen_ai.tool.call.id":                     "tool-call-1",
		"defenseclaw.tool.skill_key":              "shell.exec",
		"defenseclaw.agent.reported_cost.present": true,
	}
	for key, expected := range want {
		if actual := body[key]; actual != expected {
			t.Errorf("%s=%v (%T), want %v (%T)", key, actual, actual, expected, expected)
		}
	}
	if fmt.Sprint(body["defenseclaw.agent.reported_cost.usd"]) != "0.25" {
		t.Fatalf("reported cost=%v", body["defenseclaw.agent.reported_cost.usd"])
	}
}

func generatedContractBody(t *testing.T, record Record) map[string]any {
	t.Helper()
	body, ok := record.Body()
	if !ok {
		t.Fatal("generated record has no body")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	return object
}
