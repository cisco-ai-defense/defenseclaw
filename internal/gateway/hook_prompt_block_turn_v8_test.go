// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// hookGalileoSpanCapture binds an API server to a Galileo destination and
// returns it with that destination's span capture.
func hookGalileoSpanCapture(t *testing.T) (*APIServer, func() []*tracepb.Span) {
	t.Helper()
	galileo := &hookModelV8OTLPCapture{}
	galileoServer := httptest.NewServer(http.HandlerFunc(galileo.handler))
	t.Cleanup(galileoServer.Close)
	otlp := &hookModelV8OTLPCapture{}
	otlpServer := httptest.NewServer(http.HandlerFunc(otlp.handler))
	t.Cleanup(otlpServer.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	raw := append(hookModelV8BootstrapRaw(fixture.dataDir, otlpServer.URL, []string{"traces"}), fmt.Sprintf(
		"    - name: hook-galileo\n      kind: otlp\n      preset: galileo\n      endpoint: %q\n      protocol: http/protobuf\n"+
			"      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n"+
			"      batch:\n        max_export_batch_size: 16\n        scheduled_delay_ms: 10\n", galileoServer.URL)...)
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	return api, func() []*tracepb.Span { return hookModelV8CapturedSpansFromCapture(galileo) }
}

// waitHookGalileoSpans polls until want spans whose name starts with prefix
// arrived, and returns every span by then.
func waitHookGalileoSpans(spans func() []*tracepb.Span, prefix string, want int) []*tracepb.Span {
	var got []*tracepb.Span
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		got = spans()
		count := 0
		for _, span := range got {
			if strings.HasPrefix(span.Name, prefix) {
				count++
			}
		}
		if count >= want {
			break
		}
	}
	return got
}

// GAP-2485: a hook connector's blocked prompt never reaches the model, so no
// Stop ends its turn. The block ends it: Galileo gets the turn's agent and
// chat spans with the rule, severity and blocked outcome in their metadata,
// and the block message the user saw as the reply (GAP-2510). Claude Code
// reports the model only on SessionStart, as live.
func TestHookBlockedPromptEndsTheTurnWithTheBlockOnGalileo(t *testing.T) {
	api, spans := hookGalileoSpanCapture(t)
	const session = "claude-blocked-prompt-session"
	api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
		HookEventName: "SessionStart", SessionID: session, Model: "claude-haiku-4-5",
		Payload: map[string]any{"source": "startup", "model": "claude-haiku-4-5"},
	}, nil, nil)
	ctx := withHookToolCallCapture(t.Context(), &hookToolCallCapture{})
	api.emitClaudeCodeHookLLMEvent(ctx, claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit", SessionID: session,
		Prompt:  "Reply with one word: ok. Reference dccert-prompt-marker",
		Payload: map[string]any{"user_name": "bob"},
	}, nil, []byte(`{"prompt":"Reply with one word: ok. Reference dccert-prompt-marker"}`))
	const blockMessage = "DefenseClaw policy blocked this action (rule R6-PROMPT-MARKER: Test marker prompt). Do not retry it in another form."
	api.emitHookGuardrailOutcomeV8(ctx,
		agentHookRequest{ConnectorName: "claudecode", HookEventName: "UserPromptSubmit", SessionID: session},
		agentHookResponse{
			Action: "block", Severity: "CRITICAL", RuleIDs: []string{"R6-PROMPT-MARKER"},
			Reason: blockMessage, SourceReason: "matched: R6-PROMPT-MARKER:Test marker prompt",
		}, time.Millisecond)

	found := map[string]map[string]string{}
	// The chat span ends before its agent span, so the two can land in
	// separate export batches: wait for both.
	waitHookGalileoSpans(spans, "chat", 1)
	for _, span := range waitHookGalileoSpans(spans, "invoke_agent", 1) {
		for _, prefix := range []string{"invoke_agent", "chat"} {
			if strings.HasPrefix(span.Name, prefix) {
				found[prefix] = hookModelV8ProtoAttributes(span)
			}
		}
	}
	for _, prefix := range []string{"invoke_agent", "chat"} {
		attributes, ok := found[prefix]
		if !ok {
			t.Errorf("galileo has no %s span for the blocked turn", prefix)
			continue
		}
		metadata := attributes["metadata"]
		for _, want := range []string{
			`"defenseclaw.guardrail.action":"block"`, `"defenseclaw.guardrail.rule_id":"R6-PROMPT-MARKER"`,
			`"defenseclaw.guardrail.severity":"CRITICAL"`, `"defenseclaw.outcome":"blocked"`,
		} {
			if !strings.Contains(metadata, want) {
				t.Errorf("galileo %s span metadata=%q, want %s", prefix, metadata, want)
			}
		}
		if output := attributes["output.value"]; !strings.Contains(output, "R6-PROMPT-MARKER: Test marker prompt") ||
			strings.Contains(output, "<redacted") {
			t.Errorf("galileo %s span output=%q, want the block message %q", prefix, output, blockMessage)
		}
	}
}

// GAP-2511: Claude Code reports the model only on SessionStart, so only the
// first turn of a session had a chat span. Every turn that reached the model
// has one.
func TestHookClaudeCodeEveryTurnHasAChatSpanOnGalileo(t *testing.T) {
	api, spans := hookGalileoSpanCapture(t)
	const session = "claude-multi-turn-session"
	api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
		HookEventName: "SessionStart", SessionID: session, Model: "claude-haiku-4-5",
		Payload: map[string]any{"source": "startup", "model": "claude-haiku-4-5"},
	}, nil, nil)
	turns := []string{"ready", "after", "obs"}
	for _, word := range turns {
		prompt := "Reply with one word: " + word
		api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
			HookEventName: "UserPromptSubmit", SessionID: session, Prompt: prompt, Payload: map[string]any{},
		}, nil, []byte(`{"prompt":"`+prompt+`"}`))
		api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
			HookEventName: "Stop", SessionID: session, LastAssistantMessage: word, Payload: map[string]any{},
		}, nil, []byte(`{"last_assistant_message":"`+word+`"}`))
	}
	chats := 0
	for _, span := range waitHookGalileoSpans(spans, "chat", len(turns)) {
		if strings.HasPrefix(span.Name, "chat") {
			chats++
			if !strings.Contains(span.Name, "claude-haiku-4-5") {
				t.Errorf("chat span name=%q, want the session model", span.Name)
			}
		}
	}
	if chats != len(turns) {
		t.Fatalf("galileo chat spans=%d, want one per turn (%d)", chats, len(turns))
	}
}
