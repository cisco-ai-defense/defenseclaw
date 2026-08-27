// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestProxyV8InputMessagesFailsClosedWhenSourceIsPartiallyRepresented(t *testing.T) {
	tests := []struct {
		name     string
		messages []ChatMessage
	}{
		{
			name: "unsupported role beside valid user content",
			messages: []ChatMessage{
				{Role: "user", Content: "visible"},
				{Role: "provider_extension", Content: "must not be silently omitted"},
			},
		},
		{
			name: "assistant tool calls",
			messages: []ChatMessage{{
				Role: "assistant", ToolCalls: json.RawMessage(
					`[{"id":"call_input","type":"function","function":{"name":"weather","arguments":"{}"}}]`,
				),
			}},
		},
		{
			name: "tool response linkage",
			messages: []ChatMessage{{
				Role: "tool", Content: "sunny", ToolCallID: "call_input",
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, originalBytes, reported, state, structured := proxyV8InputMessages(test.messages)
			if !reported || state != "failed_closed" || structured || originalBytes <= 0 {
				t.Fatalf("input mapping bytes=%d reported=%t state=%q structured=%t",
					originalBytes, reported, state, structured)
			}
		})
	}
}

func TestProxyV8InputMessagesFailsClosedAboveCanonicalItemLimit(t *testing.T) {
	messages := make([]ChatMessage, proxyV8MaxStructuredItems+1)
	for index := range messages {
		messages[index] = ChatMessage{Role: "user", Content: "x"}
	}
	_, originalBytes, reported, state, structured := proxyV8InputMessages(messages)
	if !reported || state != "failed_closed" || structured ||
		originalBytes != int64(len(messages)) {
		t.Fatalf("input item bound bytes=%d reported=%t state=%q structured=%t",
			originalBytes, reported, state, structured)
	}
}

func TestSemanticRouterRawNonStreamingOversizedInputKeepsTerminalV8Spans(t *testing.T) {
	const responseModel = "qwen2.5:0.5b"
	prompt := strings.Repeat("p", 64*1024+1)
	var upstreamReached atomic.Bool
	var forwardedPromptBytes atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode routed upstream request: %v", err)
		} else if len(request.Messages) != 1 {
			t.Errorf("routed upstream message count=%d want=1", len(request.Messages))
		} else {
			forwardedPromptBytes.Store(int64(len(request.Messages[0].Content)))
		}
		upstreamReached.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-oversized-input","object":"chat.completion","model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()
	allowRawForwardPrivateTargets(t)

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider: "ollama", TargetURL: upstream.URL, TargetURLOverride: true, Model: responseModel,
	}})
	body := mustJSON(t, map[string]any{
		"model":    "openai/gpt-4o",
		"messages": []map[string]any{{"role": "user", "content": prompt}},
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	request.RemoteAddr = "127.0.0.1:12345"
	recorder := httptest.NewRecorder()

	proxy.handleChatCompletion(recorder, request)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"content":"ok"`) {
		t.Fatalf("oversized input status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !upstreamReached.Load() || forwardedPromptBytes.Load() != int64(len(prompt)) {
		t.Fatalf("routed upstream reached=%t prompt bytes=%d want=%d",
			upstreamReached.Load(), forwardedPromptBytes.Load(), len(prompt))
	}
	agent, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
	)
	for _, span := range []struct {
		name       string
		attributes map[string]any
	}{
		{name: "agent", attributes: proxyCanonicalAttributes(t, agent.Record())},
		{name: "model", attributes: proxyCanonicalAttributes(t, model.Record())},
	} {
		if reported, ok := span.attributes["defenseclaw.telemetry.input.reported"].(bool); !ok || !reported {
			t.Fatalf("%s input reported=%v present=%t", span.name, reported, ok)
		}
		if state := span.attributes["defenseclaw.content.input.state"]; state != "failed_closed" {
			t.Fatalf("%s input state=%v want failed_closed", span.name, state)
		}
		originalBytes, err := span.attributes["defenseclaw.content.input.original_bytes"].(json.Number).Int64()
		if err != nil || originalBytes != int64(len(prompt)) {
			t.Fatalf("%s input original bytes=%d err=%v want=%d", span.name, originalBytes, err, len(prompt))
		}
		if input, present := span.attributes["gen_ai.input.messages"]; present {
			t.Fatalf("%s retained invalid gen_ai.input.messages=%v", span.name, input)
		}
	}
}
