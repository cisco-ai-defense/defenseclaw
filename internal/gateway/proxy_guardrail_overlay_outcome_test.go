// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// TestProxyGuardrailOverlayStampsTheOutcome pins GAP-2332 on the proxy
// path: an enforced prompt block puts its action, rule and severity on the
// invoke_agent span, a completion block on the chat span, a later alert
// keeps the block, and an observe-mode would-block stamps nothing.
func TestProxyGuardrailOverlayStampsTheOutcome(t *testing.T) {
	facts := func(target, effective string) proxyGuardrailV8Facts {
		return proxyGuardrailV8Facts{
			targetType: target, effective: effective, decision: "block", severity: observability.SeverityHigh,
			ruleIDs: observability.Present([]string{"R6-PROMPT-MARKER"}), evaluationID: uuid.NewString(),
			observedAt: time.Now().UTC(),
		}
	}
	request := &proxyV8RequestTrace{agent: &observabilityruntime.AgentTrace{}}
	request.AddGuardrailOverlay(facts("prompt", "block").overlay(context.Background()))
	alert := facts("prompt", "alert")
	alert.ruleIDs = observability.Present([]string{"OTHER-RULE"})
	request.AddGuardrailOverlay(alert.overlay(context.Background()))
	assertGuardrailAttributes(t, "agent", request.agentInput.DefenseClawGuardrailAction,
		request.agentInput.DefenseClawGuardrailRuleID, request.agentInput.DefenseClawGuardrailSeverity)

	model := &proxyV8ModelTrace{model: &observabilityruntime.ModelTrace{}}
	model.AddGuardrailOverlay(facts("completion", "block").overlay(context.Background()))
	assertGuardrailAttributes(t, "chat", model.input.DefenseClawGuardrailAction,
		model.input.DefenseClawGuardrailRuleID, model.input.DefenseClawGuardrailSeverity)

	observed := &proxyV8RequestTrace{agent: &observabilityruntime.AgentTrace{}}
	observed.AddGuardrailOverlay(facts("prompt", "allow").overlay(context.Background()))
	if observed.agentInput.DefenseClawGuardrailAction.IsPresent() {
		t.Fatal("an observe-mode would-block stamped a guardrail action")
	}
}

func assertGuardrailAttributes(t *testing.T, family string, action, rule, severity observability.Optional[string]) {
	t.Helper()
	a, _ := action.Get()
	r, _ := rule.Get()
	s, _ := severity.Get()
	if a != "block" || r != "R6-PROMPT-MARKER" || s != "HIGH" {
		t.Fatalf("%s guardrail = %q/%q/%q, want block/R6-PROMPT-MARKER/HIGH", family, a, r, s)
	}
}
