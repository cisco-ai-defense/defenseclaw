// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestAdjudicateFindingsKeepsSecretSeparateFromPII(t *testing.T) {
	response := &ChatResponse{
		Model: "test-model",
		Choices: []ChatChoice{{Message: &ChatMessage{Content: `{
			"findings":[{"pattern":"candidate","verdict":"true_positive","reasoning":"confirmed"}],
			"overall_threat":true,
			"severity":"HIGH"
		}`}}},
	}
	provider := &mockLLMProvider{response: response}
	judge := &LLMJudge{
		cfg:      &config.JudgeConfig{Enabled: true},
		model:    "test-model",
		provider: provider,
		rp:       &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{}},
	}

	verdict := judge.AdjudicateFindings(t.Context(), "completion", "credential output", []TriageSignal{
		{Category: "pii", Pattern: "ssn", Evidence: "candidate"},
		{Category: "secret", Pattern: "bearer", Evidence: "candidate"},
	})
	if verdict == nil {
		t.Fatal("nil verdict")
	}
	joined := strings.Join(verdict.Findings, " ")
	for _, want := range []string{"JUDGE-ADJ-PII", "JUDGE-ADJ-SECRET"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("findings=%v, missing %s", verdict.Findings, want)
		}
	}

	provider.mu.Lock()
	captured := append([]*ChatRequest(nil), provider.captured...)
	provider.mu.Unlock()
	if len(captured) != 2 {
		t.Fatalf("judge calls=%d, want separate PII and secret lanes", len(captured))
	}
	var sawPII, sawSecret bool
	for _, request := range captured {
		if len(request.Messages) == 0 {
			continue
		}
		system := request.Messages[0].Content
		sawPII = sawPII || strings.Contains(system, "PII adjudicator")
		sawSecret = sawSecret || strings.Contains(system, "credential-leak adjudicator")
	}
	if !sawPII || !sawSecret {
		t.Fatalf("separate prompts observed: pii=%v secret=%v", sawPII, sawSecret)
	}
}

func TestParseAdjudicationResponseSecretIdentity(t *testing.T) {
	verdict := parseAdjudicationResponse(`{
		"findings":[{"pattern":"candidate","verdict":"true_positive","reasoning":"confirmed"}],
		"overall_threat":true,
		"severity":"HIGH"
	}`, "secret")
	if verdict == nil || len(verdict.Findings) != 1 ||
		verdict.Findings[0] != "JUDGE-ADJ-SECRET" ||
		verdict.Reason != "judge-adjudicate-secret" {
		t.Fatalf("secret verdict=%+v", verdict)
	}
}

// GAP-0351: a suppression saved with --connector lives in that connector
// composed pack, not in the global pack the judge is built with; the
// hook-lane run must apply it.
func TestJudgeAppliesTheConnectorPackSuppressions(t *testing.T) {
	j := testJudge(t)
	data := map[string]interface{}{
		"Email Address": map[string]interface{}{
			"detection_result": true,
			"entities":         []interface{}{"ci-bot@build.acme.example"},
		},
	}
	if v := j.piiToVerdictWith(j.suppressionPack(context.Background()), data, "completion", ""); v.Action != "block" {
		t.Fatalf("global pack: action = %q, want block", v.Action)
	}
	connectorPack := &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{
		FindingSupps: []guardrail.FindingSuppression{
			{ID: "C-EMAIL", FindingPattern: "JUDGE-PII-EMAIL", EntityPattern: ".*", Reason: "ci bot"},
		},
	}}
	ctx := withJudgeSuppressionPack(context.Background(), connectorPack)
	if v := j.piiToVerdictWith(j.suppressionPack(ctx), data, "completion", ""); v.Action != "allow" {
		t.Fatalf("connector pack: action = %q findings=%v, want allow", v.Action, v.Findings)
	}
}
