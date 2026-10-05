// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-2641: judge spans are their own traces, so without the caller and turn
// identity of the hook request they could not be attributed to a user.
func TestLocalJudgeGeneratedSpanCarriesCallerIdentity(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	finishReason := "stop"
	judge := &LLMJudge{
		cfg:   &config.JudgeConfig{Enabled: true, PII: true},
		model: "openai/gpt-judge", providerName: "openai",
		provider: &mockLLMProvider{response: &ChatResponse{
			ID: "judge-response-001", Model: "openai/gpt-judge",
			Choices: []ChatChoice{{
				Message: &ChatMessage{Role: "assistant", Content: allCleanPIIJSON}, FinishReason: &finishReason,
			}},
		}},
		rp: &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{}},
	}
	judge.bindJudgeTraceV8(runtime)

	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{
		Connector: "claudecode", SessionID: "session-2641", TurnID: "turn-2641", RequestID: "request-2641",
	})
	ctx = ContextWithAgentIdentity(ctx, AgentIdentity{
		UserID: "501", UserIDKind: useridentity.KindPOSIXUID, UserName: "dcm-std1",
	})
	judge.runPIIJudge(ctx, strings.Repeat("p", 40), "prompt", "")

	spans := capture.snapshot()
	if len(spans) != 1 {
		t.Fatalf("generated judge spans=%d, want 1", len(spans))
	}
	attributes := proxyCanonicalAttributes(t, spans[0].Record())
	for key, want := range map[string]string{
		"user.id":                      "501",
		"defenseclaw.user.id_kind":     useridentity.KindPOSIXUID,
		"defenseclaw.user.name":        "dcm-std1",
		"defenseclaw.turn.id":          "turn-2641",
		"defenseclaw.request.id":       "request-2641",
		"gen_ai.conversation.id":       "session-2641",
		"defenseclaw.connector.source": "claudecode",
	} {
		if got := attributes[key]; got != want {
			t.Errorf("%s=%v, want %q", key, got, want)
		}
	}
}
