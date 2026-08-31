// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestProxyV8OutputMessagesFailsClosedAboveCanonicalPartLimit(t *testing.T) {
	calls := make([]map[string]any, proxyV8MaxStructuredItems+1)
	for index := range calls {
		calls[index] = map[string]any{
			"id": "call_boundary", "type": "function",
			"function": map[string]any{"name": "weather", "arguments": `{}`},
		}
	}
	raw, err := json.Marshal(calls)
	if err != nil {
		t.Fatal(err)
	}
	_, originalBytes, reported, state, structured := proxyV8OutputMessages("", raw, nil)
	if !reported || state != "failed_closed" || structured || originalBytes != int64(len(raw)) {
		t.Fatalf("output part bound bytes=%d reported=%t state=%q structured=%t",
			originalBytes, reported, state, structured)
	}
}

func TestSemanticRouterRawNonStreamingOversizedAssistantOutputKeepsTerminalV8Spans(t *testing.T) {
	const responseModel = "qwen2.5:0.5b"
	output := strings.Repeat("x", 64*1024+1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl-oversized-output", "object": "chat.completion", "model": responseModel,
			"choices": []map[string]any{{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": output},
				"finish_reason": "stop",
			}},
		}); err != nil {
			t.Errorf("encode upstream response: %v", err)
		}
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
	recorder := routedRawV8BoundaryRequest(t, proxy, false)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), output[:64]) {
		t.Fatalf("oversized raw response status=%d forwarded_prefix=%t", recorder.Code,
			strings.Contains(recorder.Body.String(), output[:64]))
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
		assertRawV8OutputFailedClosed(t, span.name, span.attributes)
		originalBytes, err := span.attributes["defenseclaw.content.output.original_bytes"].(json.Number).Int64()
		if err != nil || originalBytes != int64(len(output)) {
			t.Fatalf("%s output original bytes=%d err=%v want=%d", span.name, originalBytes, err, len(output))
		}
	}
}

func TestSemanticRouterRawNonStreamingOversizedOrDeepToolArgumentsKeepTerminalV8Spans(t *testing.T) {
	deepArguments := `"leaf"`
	for range 16 {
		deepArguments = `{"nested":` + deepArguments + `}`
	}
	tests := []struct {
		name      string
		arguments string
	}{
		{name: "oversized", arguments: `{"payload":"` + strings.Repeat("x", 64*1024+1) + `"}`},
		{name: "deep", arguments: deepArguments},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const responseModel = "qwen2.5:0.5b"
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{
					"id":     "chatcmpl-bounded-tool-" + test.name,
					"object": "chat.completion", "model": responseModel,
					"choices": []map[string]any{{
						"index": 0,
						"message": map[string]any{
							"role": "assistant",
							"tool_calls": []map[string]any{{
								"id": "call_boundary", "type": "function",
								"function": map[string]any{"name": "weather", "arguments": test.arguments},
							}},
						},
						"finish_reason": "tool_calls",
					}},
				}); err != nil {
					t.Errorf("encode upstream response: %v", err)
				}
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
			recorder := routedRawV8BoundaryRequest(t, proxy, false)

			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "call_boundary") {
				t.Fatalf("bounded tool response status=%d forwarded_call=%t", recorder.Code,
					strings.Contains(recorder.Body.String(), "call_boundary"))
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
				assertRawV8OutputFailedClosed(t, span.name, span.attributes)
			}
			toolCount, err := proxyCanonicalAttributes(t, model.Record())["defenseclaw.model.tool_call_count"].(json.Number).Int64()
			if err != nil || toolCount != 1 {
				t.Fatalf("bounded tool count=%d err=%v", toolCount, err)
			}
		})
	}
}

func TestSemanticRouterRawNegativeUsageIsOmittedFromTerminalV8Telemetry(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "non_stream"
		if stream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			const responseModel = "qwen2.5:0.5b"
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				usage := map[string]int64{
					"prompt_tokens": -11, "completion_tokens": -7, "total_tokens": -18,
				}
				if !stream {
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]any{
						"id": "chatcmpl-negative-usage", "object": "chat.completion", "model": responseModel,
						"choices": []map[string]any{{
							"index":         0,
							"message":       map[string]any{"role": "assistant", "content": "ok"},
							"finish_reason": "stop",
						}},
						"usage": usage,
					}); err != nil {
						t.Errorf("encode upstream response: %v", err)
					}
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				chunk, err := json.Marshal(map[string]any{
					"id": "chatcmpl-negative-usage", "object": "chat.completion.chunk", "model": responseModel,
					"choices": []map[string]any{{
						"index": 0, "delta": map[string]any{"content": "ok"}, "finish_reason": "stop",
					}},
					"usage": usage,
				})
				if err != nil {
					t.Errorf("encode upstream stream chunk: %v", err)
					return
				}
				_, _ = w.Write(append(append([]byte("data: "), chunk...), '\n', '\n'))
				_, _ = io.WriteString(w, "data: [DONE]\n\n")
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
			recorder := routedRawV8BoundaryRequest(t, proxy, stream)

			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "ok") {
				t.Fatalf("negative usage response status=%d forwarded_output=%t", recorder.Code,
					strings.Contains(recorder.Body.String(), "ok"))
			}
			_, model := assertProxyGeneratedAgentModel(
				t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
			)
			attributes := proxyCanonicalAttributes(t, model.Record())
			if reported, ok := attributes["defenseclaw.telemetry.tokens.reported"].(bool); !ok || reported {
				t.Fatalf("negative usage tokens reported=%v present=%t", reported, ok)
			}
			for _, key := range []string{"gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens"} {
				if value, reported := attributes[key]; reported {
					t.Fatalf("negative usage reported %s=%v", key, value)
				}
			}
			for _, metric := range capture.metricSnapshot() {
				if metric.Descriptor().Name == observability.TelemetryInstrumentGenAIClientTokenUsage {
					t.Fatalf("negative usage emitted token metric: %v", metric)
				}
			}
		})
	}
}

func routedRawV8BoundaryRequest(t *testing.T, proxy *GuardrailProxy, stream bool) *httptest.ResponseRecorder {
	t.Helper()
	body := mustJSON(t, map[string]any{
		"model": "openai/gpt-4o", "stream": stream,
		"messages": []map[string]any{{"role": "user", "content": "Exercise a telemetry boundary."}},
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	request.RemoteAddr = "127.0.0.1:12345"
	recorder := httptest.NewRecorder()
	proxy.handleChatCompletion(recorder, request)
	return recorder
}

func assertRawV8OutputFailedClosed(t *testing.T, spanName string, attributes map[string]any) {
	t.Helper()
	if reported, ok := attributes["defenseclaw.telemetry.output.reported"].(bool); !ok || !reported {
		t.Fatalf("%s output reported=%v present=%t", spanName, reported, ok)
	}
	if state := attributes["defenseclaw.content.output.state"]; state != "failed_closed" {
		t.Fatalf("%s output state=%v want failed_closed", spanName, state)
	}
	if output, reported := attributes["gen_ai.output.messages"]; reported {
		t.Fatalf("%s retained invalid gen_ai.output.messages=%v", spanName, output)
	}
}
