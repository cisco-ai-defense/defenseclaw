// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// GAP-2584: after GAP-2556 Claude Code chat spans named the Bedrock model ID
// ("anthropic.claude-haiku-4-5-20251001-v1:0"), while OpenClaw kept the
// inference profile ("us.anthropic.claude-haiku-4-5-20251001-v1:0"), so one
// model showed up as two in Galileo. Every connector now names the model ID.
func TestOpenClawBedrockChatSpanNamesTheSameModelAsClaudeCode(t *testing.T) {
	const profile = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
	const model = "anthropic.claude-haiku-4-5-20251001-v1:0"
	router, capture := bindEventRouterModelV8Runtime(t, []string{"traces"})
	payload, err := json.Marshal(map[string]any{
		"sessionKey": "session-bedrock-1", "runId": "run-bedrock-1",
		"messageId": "message-bedrock-1", "messageSeq": 1,
		"message": map[string]any{
			"role":     "assistant",
			"content":  []map[string]any{{"type": "text", "text": "ready"}},
			"provider": "amazon-bedrock", "model": profile, "stopReason": "end_turn",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	router.handleSessionMessage(EventFrame{Type: "event", Event: "session.message", Payload: payload})
	chats := 0
	for _, span := range waitForEventRouterModelSpans(t, capture, 2) {
		if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") != observability.TelemetryFamilyModelChat {
			continue
		}
		chats++
		if span.Name != "chat "+model {
			t.Errorf("OpenClaw chat span name=%q, want %q", span.Name, "chat "+model)
		}
		if got := gatewayProtoAttribute(span.Attributes, "gen_ai.request.model"); got != model {
			t.Errorf("OpenClaw gen_ai.request.model=%q, want %q", got, model)
		}
	}
	if chats != 1 {
		t.Fatalf("OpenClaw chat spans=%d, want 1", chats)
	}

	// The other hook connectors (Codex, OpenCode, Hermes, ...) and the
	// OpenClaw stream meta take the same model ID; other IDs are unchanged.
	if got := hookLLMEventMeta(t.Context(), "codex", "s1", "t1", profile, "", "", "", "", map[string]interface{}{}).Model; got != model {
		t.Errorf("hook connector model=%q, want %q", got, model)
	}
	if got := streamLLMEventMeta(router, "s1", "r1", "amazon-bedrock", profile, "").Model; got != model {
		t.Errorf("OpenClaw stream model=%q, want %q", got, model)
	}
	if got := telemetryModelID("us.openai.gpt-5.6-luna"); got != "us.openai.gpt-5.6-luna" {
		t.Errorf("non-Anthropic profile=%q, want it unchanged", got)
	}
}
