// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// GAP-0370: every model-text field the client receives (answer, thinking or
// reasoning, refusal, streamed tool input, every choice) reaches the
// completion checks, streamed and not, on the passthrough, /llm and raw
// forward paths. The marker stands for a finding: the inspector below blocks
// any completion text that holds it, so a case passes only when the field
// was read and the client did not get it.
const respFieldMarker = "qzx-respfield-marker"

type fieldMarkerInspector struct {
	mu   sync.Mutex
	seen bool
}

func (m *fieldMarkerInspector) Inspect(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	if direction != "completion" || !strings.Contains(content, respFieldMarker) {
		return allowVerdict("marker")
	}
	m.mu.Lock()
	m.seen = true
	m.mu.Unlock()
	return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "marker"}
}

func (m *fieldMarkerInspector) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return m.Inspect(ctx, direction, content, messages, model, mode)
}

func (m *fieldMarkerInspector) SetScannerMode(string) {}

func (m *fieldMarkerInspector) SetHILTConfig(bool, string) {}

func (m *fieldMarkerInspector) sawMarker() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen
}

// jsonText is s as a JSON string literal.
func jsonText(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func sseBody(events ...string) string {
	var sb strings.Builder
	for _, e := range events {
		sb.WriteString("data: " + e + "\n\n")
	}
	return sb.String()
}

func ndjsonBody(events ...string) string {
	return strings.Join(events, "\n") + "\n"
}

// eventStreamBody encodes AWS eventstream event messages: pairs of event
// type and JSON payload.
func eventStreamBody(t *testing.T, typeAndPayload ...string) string {
	t.Helper()
	var buf bytes.Buffer
	enc := eventstream.NewEncoder()
	for i := 0; i+1 < len(typeAndPayload); i += 2 {
		if err := enc.Encode(&buf, eventstream.Message{Headers: eventstream.Headers{
			{Name: ":message-type", Value: eventstream.StringValue("event")},
			{Name: ":event-type", Value: eventstream.StringValue(typeAndPayload[i])},
		}, Payload: []byte(typeAndPayload[i+1])}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.String()
}

// invokeChunk wraps one model event as an InvokeModelWithResponseStream chunk.
func invokeChunk(event string) string {
	payload, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(event))})
	return string(payload)
}

type passthroughFieldCase struct {
	name        string
	provider    string
	path        string
	contentType string
	body        string
}

const (
	ctJSON   = "application/json"
	ctSSE    = "text/event-stream"
	ctNDJSON = "application/x-ndjson"
	ctEvents = "application/vnd.amazon.eventstream"
)

func passthroughRequestBody(provider string) string {
	switch provider {
	case "anthropic":
		return `{"model":"claude-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`
	case "gemini":
		return `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
	case "ollama":
		return `{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`
	case "bedrock":
		return `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`
	default:
		return `{"model":"gpt-x","input":"hi"}`
	}
}

// runPassthroughFieldCase sends one request through the passthrough proxy in
// action mode to an upstream that answers with the case body.
func runPassthroughFieldCase(t *testing.T, c passthroughFieldCase) (saw bool, out string) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", c.contentType)
		_, _ = writeFieldBody(w, c.body)
	}))
	defer upstream.Close()
	registerRawForwardProviderDomain(t, upstream.URL, c.provider)
	allowRawForwardPrivateTargets(t)
	insp := &fieldMarkerInspector{}
	proxy := newTestProxy(t, &mockProvider{}, insp, "action")
	req := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(passthroughRequestBody(c.provider)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer test-key")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, req)
	return insp.sawMarker(), rec.Body.String()
}

func writeFieldBody(w http.ResponseWriter, s string) (int, error) { return w.Write([]byte(s)) }

func passthroughFieldCases(t *testing.T) []passthroughFieldCase {
	M := jsonText(respFieldMarker)
	half1, half2 := jsonText(respFieldMarker[:9]), jsonText(respFieldMarker[9:])
	return []passthroughFieldCase{
		// Anthropic Messages.
		{"anthropic/body/text", "anthropic", "/v1/messages", ctJSON,
			`{"type":"message","role":"assistant","content":[{"type":"text","text":` + M + `}]}`},
		{"anthropic/body/thinking", "anthropic", "/v1/messages", ctJSON,
			`{"type":"message","role":"assistant","content":[{"type":"thinking","thinking":` + M + `,"signature":"sig"},{"type":"text","text":"ok"}]}`},
		{"anthropic/stream/text_delta", "anthropic", "/v1/messages", ctSSE, sseBody(
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":` + M + `}}`)},
		{"anthropic/stream/thinking_delta", "anthropic", "/v1/messages", ctSSE, sseBody(
			`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":`+M+`}}`)},
		{"anthropic/stream/input_json_delta", "anthropic", "/v1/messages", ctSSE, sseBody(
			`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"echo `+respFieldMarker[:9]+`"}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"`+respFieldMarker[9:]+`\"}"}}`)},
		// OpenAI Responses.
		{"responses/body/output_text", "openai", "/v1/responses", ctJSON,
			`{"output":[{"type":"message","content":[{"type":"output_text","text":` + M + `}]}]}`},
		{"responses/body/refusal", "openai", "/v1/responses", ctJSON,
			`{"output":[{"type":"message","content":[{"type":"refusal","refusal":` + M + `}]}]}`},
		{"responses/body/reasoning_summary", "openai", "/v1/responses", ctJSON,
			`{"output":[{"type":"reasoning","summary":[{"type":"summary_text","text":` + M + `}]},{"type":"message","content":[{"type":"output_text","text":"ok"}]}]}`},
		{"responses/stream/output_text", "openai", "/v1/responses", ctSSE, sseBody(
			`{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":` + M + `}`)},
		{"responses/stream/refusal", "openai", "/v1/responses", ctSSE, sseBody(
			`{"type":"response.refusal.delta","output_index":0,"content_index":0,"delta":` + M + `}`)},
		{"responses/stream/reasoning_summary", "openai", "/v1/responses", ctSSE, sseBody(
			`{"type":"response.reasoning_summary_text.delta","output_index":0,"summary_index":0,"delta":` + M + `}`)},
		{"responses/stream/function_call_arguments", "openai", "/v1/responses", ctSSE, sseBody(
			`{"type":"response.function_call_arguments.delta","output_index":1,"delta":`+half1+`}`,
			`{"type":"response.function_call_arguments.delta","output_index":1,"delta":`+half2+`}`)},
		// OpenAI chat shape on a passthrough path (legacy completions and
		// OpenAI-compatible servers).
		{"chatshape/body/choice1", "openai", "/v1/completions", ctJSON,
			`{"choices":[{"index":0,"message":{"content":"ok"}},{"index":1,"message":{"content":` + M + `}}]}`},
		{"chatshape/body/refusal", "openai", "/v1/completions", ctJSON,
			`{"choices":[{"index":0,"message":{"content":null,"refusal":` + M + `}}]}`},
		{"chatshape/body/reasoning_content", "openai", "/v1/completions", ctJSON,
			`{"choices":[{"index":0,"message":{"content":"ok","reasoning_content":` + M + `}}]}`},
		{"chatshape/body/legacy_text", "openai", "/v1/completions", ctJSON,
			`{"choices":[{"index":0,"text":` + M + `}]}`},
		{"chatshape/stream/choice1", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"content":"ok"}},{"index":1,"delta":{"content":` + M + `}}]}`)},
		{"chatshape/stream/choice0_interleaved", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"content":`+half1+`}}]}`,
			`{"choices":[{"index":1,"delta":{"content":"other words"}}]}`,
			`{"choices":[{"index":0,"delta":{"content":`+half2+`}}]}`)},
		{"chatshape/stream/reasoning", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"reasoning":` + M + `}}]}`)},
		{"chatshape/stream/tool_arguments", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"bash","arguments":`+half1+`}}]}}]}`,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":`+half2+`}}]}}]}`)},
		// Gemini.
		{"gemini/body/candidate1", "gemini", "/v1beta/models/gemini-x:generateContent", ctJSON,
			`{"candidates":[{"index":0,"content":{"parts":[{"text":"ok"}]}},{"index":1,"content":{"parts":[{"text":` + M + `}]}}]}`},
		{"gemini/body/thought", "gemini", "/v1beta/models/gemini-x:generateContent", ctJSON,
			`{"candidates":[{"content":{"parts":[{"text":` + M + `,"thought":true},{"text":"ok"}]}}]}`},
		{"gemini/stream/text", "gemini", "/v1beta/models/gemini-x:streamGenerateContent", ctSSE, sseBody(
			`{"candidates":[{"index":0,"content":{"parts":[{"text":` + M + `}]}}]}`)},
		{"gemini/stream/candidate1", "gemini", "/v1beta/models/gemini-x:streamGenerateContent", ctSSE, sseBody(
			`{"candidates":[{"index":0,"content":{"parts":[{"text":"ok"}]}},{"index":1,"content":{"parts":[{"text":` + M + `}]}}]}`)},
		{"gemini/stream/function_call_args", "gemini", "/v1beta/models/gemini-x:streamGenerateContent", ctSSE, sseBody(
			`{"candidates":[{"index":0,"content":{"parts":[{"functionCall":{"name":"run","args":{"command":` + M + `}}}]}}]}`)},
		// Ollama native.
		{"ollama/body/content", "ollama", "/api/chat", ctJSON,
			`{"model":"llama3","message":{"role":"assistant","content":` + M + `},"done":true}`},
		{"ollama/body/thinking", "ollama", "/api/chat", ctJSON,
			`{"model":"llama3","message":{"role":"assistant","content":"ok","thinking":` + M + `},"done":true}`},
		{"ollama/stream/content", "ollama", "/api/chat", ctNDJSON, ndjsonBody(
			`{"model":"llama3","message":{"role":"assistant","content":`+half1+`},"done":false}`,
			`{"model":"llama3","message":{"role":"assistant","content":`+half2+`},"done":false}`,
			`{"model":"llama3","message":{"role":"assistant","content":""},"done":true}`)},
		{"ollama/stream/thinking", "ollama", "/api/chat", ctNDJSON, ndjsonBody(
			`{"model":"llama3","message":{"role":"assistant","content":"","thinking":`+M+`},"done":false}`,
			`{"model":"llama3","message":{"role":"assistant","content":"ok"},"done":true}`)},
		{"ollama/stream/generate_thinking", "ollama", "/api/generate", ctNDJSON, ndjsonBody(
			`{"model":"llama3","response":"","thinking":`+M+`,"done":false}`,
			`{"model":"llama3","response":"ok","done":true}`)},
		// Bedrock: Converse and InvokeModel (Claude), bodies and eventstreams.
		{"bedrock/body/converse_text", "bedrock", "/model/m/converse", ctJSON,
			`{"output":{"message":{"role":"assistant","content":[{"text":` + M + `}]}}}`},
		{"bedrock/body/converse_reasoning", "bedrock", "/model/m/converse", ctJSON,
			`{"output":{"message":{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{"text":` + M + `,"signature":"s"}}},{"text":"ok"}]}}}`},
		{"bedrock/body/invoke_thinking", "bedrock", "/model/m/invoke", ctJSON,
			`{"type":"message","role":"assistant","content":[{"type":"thinking","thinking":` + M + `},{"type":"text","text":"ok"}]}`},
		{"bedrock/stream/converse_text", "bedrock", "/model/m/converse-stream", ctEvents, eventStreamBody(t,
			"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":`+M+`}}`)},
		{"bedrock/stream/converse_reasoning", "bedrock", "/model/m/converse-stream", ctEvents, eventStreamBody(t,
			"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"reasoningContent":{"text":`+M+`}}}`)},
		{"bedrock/stream/converse_tool_input", "bedrock", "/model/m/converse-stream", ctEvents, eventStreamBody(t,
			"contentBlockStart", `{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"t1","name":"run"}}}`,
			"contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":`+jsonText(`{"command":"`+respFieldMarker[:9])+`}}}`,
			"contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":`+jsonText(respFieldMarker[9:]+`"}`)+`}}}`)},
		{"bedrock/stream/invoke_thinking", "bedrock", "/model/m/invoke-with-response-stream", ctEvents, eventStreamBody(t,
			"chunk", invokeChunk(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":`+M+`}}`))},
		{"bedrock/stream/invoke_tool_input", "bedrock", "/model/m/invoke-with-response-stream", ctEvents, eventStreamBody(t,
			"chunk", invokeChunk(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":`+jsonText(`{"command":"`+respFieldMarker+`"}`)+`}}`))},
	}
}

func TestPassthroughChecksEveryResponseField(t *testing.T) {
	for _, c := range passthroughFieldCases(t) {
		t.Run(c.name, func(t *testing.T) {
			saw, out := runPassthroughFieldCase(t, c)
			if !saw {
				t.Errorf("the completion checks never read the field")
			}
			if strings.Contains(out, respFieldMarker) || (c.contentType == ctEvents && out == c.body) {
				t.Errorf("the field reached the client (%d bytes)", len(out))
			}
		})
	}
}

// TestResponseFieldsStayInTheirLane keeps choices and Responses summaries
// separate, but checks the same-choice thinking-to-answer boundary.
func TestResponseFieldsStayInTheirLane(t *testing.T) {
	half1, half2 := jsonText(respFieldMarker[:9]), jsonText(respFieldMarker[9:])
	for _, c := range []passthroughFieldCase{
		{"responses/reasoning_then_answer", "openai", "/v1/responses", ctSSE, sseBody(
			`{"type":"response.reasoning_summary_text.delta","output_index":0,"summary_index":0,"delta":`+half1+`}`,
			`{"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":`+half2+`}`)},
		{"chatshape/choice0_then_choice1", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"content":` + half1 + `}},{"index":1,"delta":{"content":` + half2 + `}}]}`)},
		{"anthropic/thinking_then_text", "anthropic", "/v1/messages", ctJSON,
			`{"type":"message","role":"assistant","content":[{"type":"thinking","thinking":` + half1 + `},{"type":"text","text":` + half2 + `}]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantSaw := c.name == "anthropic/thinking_then_text"
			if saw, _ := runPassthroughFieldCase(t, c); saw != wantSaw {
				t.Errorf("boundary verdict: saw=%v want=%v", saw, wantSaw)
			}
		})
	}
}

// --- /llm (provider adapter) -----------------------------------------------

const respFieldBlockedTool = `[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{\"command\":\"rm -rf /\"}"}}]`

func llmStreamRequest(t *testing.T, stream bool) []byte {
	return mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
		"stream":   stream,
	})
}

func TestLLMChecksEveryChoice(t *testing.T) {
	half1, half2 := respFieldMarker[:9], respFieldMarker[9:]
	chunk := func(choices ...ChatChoice) StreamChunk {
		return StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4", Choices: choices}
	}
	cases := []struct {
		name   string
		prov   *mockProvider
		stream bool
		leak   string
	}{
		{"body/choice1_content", &mockProvider{response: &ChatResponse{ID: "r", Object: "chat.completion", Model: "gpt-4", Choices: []ChatChoice{
			{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "ok"}, FinishReason: strPtr("stop")},
			{Index: 1, Message: &ChatMessage{Role: "assistant", Content: respFieldMarker}, FinishReason: strPtr("stop")},
		}}}, false, respFieldMarker},
		{"body/content_blocks", &mockProvider{response: &ChatResponse{ID: "r", Object: "chat.completion", Model: "gpt-4", Choices: []ChatChoice{
			{Index: 0, Message: &ChatMessage{Role: "assistant", RawContent: json.RawMessage(`[{"type":"text","text":"ok "},{"type":"refusal","refusal":` + jsonText(respFieldMarker) + `}]`)}, FinishReason: strPtr("stop")},
		}}}, false, respFieldMarker},
		{"body/choice1_tool_call", &mockProvider{response: &ChatResponse{ID: "r", Object: "chat.completion", Model: "gpt-4", Choices: []ChatChoice{
			{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "ok"}, FinishReason: strPtr("stop")},
			{Index: 1, Message: &ChatMessage{Role: "assistant", ToolCalls: json.RawMessage(respFieldBlockedTool)}, FinishReason: strPtr("tool_calls")},
		}}}, false, "rm -rf"},
		{"stream/choice1_content", &mockProvider{streamChunks: []StreamChunk{
			chunk(ChatChoice{Index: 0, Delta: &ChatMessage{Content: "ok"}}, ChatChoice{Index: 1, Delta: &ChatMessage{Content: respFieldMarker}}),
		}}, true, respFieldMarker},
		{"stream/choice0_interleaved", &mockProvider{streamChunks: []StreamChunk{
			chunk(ChatChoice{Index: 0, Delta: &ChatMessage{Content: half1}}),
			chunk(ChatChoice{Index: 1, Delta: &ChatMessage{Content: "other words"}}),
			chunk(ChatChoice{Index: 0, Delta: &ChatMessage{Content: half2}}),
		}}, true, half2},
		{"stream/choice1_tool_call", &mockProvider{streamChunks: []StreamChunk{
			chunk(ChatChoice{Index: 0, Delta: &ChatMessage{Content: "ok"}},
				ChatChoice{Index: 1, Delta: &ChatMessage{ToolCalls: json.RawMessage(respFieldBlockedTool)}}),
			chunk(ChatChoice{Index: 0, Delta: &ChatMessage{}, FinishReason: strPtr("stop")},
				ChatChoice{Index: 1, Delta: &ChatMessage{}, FinishReason: strPtr("tool_calls")}),
		}}, true, "rm -rf"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			insp := &fieldMarkerInspector{}
			proxy := newTestProxy(t, c.prov, insp, "action")
			rec := postChat(t, proxy, llmStreamRequest(t, c.stream))
			out := rec.Body.String()
			if strings.Contains(out, c.leak) || !strings.Contains(out, "blocked") {
				t.Errorf("not blocked: %d %s", rec.Code, out)
			}
		})
	}
}

// --- raw forward (OpenAI-compatible upstream, raw bytes to the client) ------

func TestRawForwardChecksEveryResponseField(t *testing.T) {
	M := jsonText(respFieldMarker)
	half1, half2 := jsonText(respFieldMarker[:9]), jsonText(respFieldMarker[9:])
	cases := []struct {
		name   string
		stream bool
		body   string
	}{
		{"body/content", false, `{"id":"r","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":` + M + `}}]}`},
		{"body/reasoning_content", false, `{"id":"r","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok","reasoning_content":` + M + `}}]}`},
		{"body/reasoning", false, `{"id":"r","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok","reasoning":` + M + `}}]}`},
		{"body/refusal", false, `{"id":"r","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":null,"refusal":` + M + `}}]}`},
		{"body/choice1", false, `{"id":"r","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}},{"index":1,"message":{"role":"assistant","content":` + M + `}}]}`},
		{"stream/content", true, sseBody(`{"id":"s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":`+M+`}}]}`, "[DONE]")},
		{"stream/reasoning_content", true, sseBody(`{"id":"s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"reasoning_content":`+M+`}}]}`, "[DONE]")},
		{"stream/reasoning", true, sseBody(`{"id":"s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"reasoning":`+M+`}}]}`, "[DONE]")},
		{"stream/refusal", true, sseBody(`{"id":"s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"refusal":`+M+`}}]}`, "[DONE]")},
		{"stream/choice0_interleaved", true, sseBody(
			`{"id":"s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":`+half1+`}}]}`,
			`{"id":"s","object":"chat.completion.chunk","choices":[{"index":1,"delta":{"content":"other words"}}]}`,
			`{"id":"s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":`+half2+`}}]}`, "[DONE]")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ct := ctJSON
			if c.stream {
				ct = ctSSE
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", ct)
				_, _ = writeFieldBody(w, c.body)
			}))
			defer upstream.Close()
			registerRawForwardProviderDomain(t, upstream.URL, "openai")
			allowRawForwardPrivateTargets(t)
			insp := &fieldMarkerInspector{}
			proxy := newTestProxy(t, &mockProvider{}, insp, "action")
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(llmStreamRequest(t, c.stream)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DC-Target-URL", upstream.URL)
			req.Header.Set("X-AI-Auth", "Bearer sk-test")
			req.RemoteAddr = "127.0.0.1:12345"
			rec := httptest.NewRecorder()
			proxy.handleChatCompletion(rec, req)
			out := rec.Body.String()
			if !insp.sawMarker() || strings.Contains(out, respFieldMarker[9:]) {
				t.Errorf("not blocked (read=%v): %d %s", insp.sawMarker(), rec.Code, out)
			}
		})
	}
}

// TestPassthroughInspectsOllamaToolCalls: a native Ollama tool call goes
// through the tool-call check like the other providers' calls.
func TestPassthroughInspectsOllamaToolCalls(t *testing.T) {
	_, out := runPassthroughFieldCase(t, passthroughFieldCase{"ollama/body/tool_call", "ollama", "/api/chat", ctJSON,
		`{"model":"llama3","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"shell","arguments":{"command":"rm -rf /"}}}]},"done":true}`})
	if strings.Contains(out, "rm -rf") || !strings.Contains(out, "blocked") {
		t.Fatalf("the tool call reached the client: %s", out)
	}
}

// syntheticGitHubToken is a GitHub token shape built at run time from a
// seeded generator: no key literal in the tree.
func syntheticGitHubToken(seed int64) string {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, 36)
	for i := range b {
		b[i] = alnum[r.Intn(len(alnum))]
	}
	return "gh" + "p_" + string(b)
}

// TestPassthroughRealDetectorsReadThinkingAndToolInput: the real inspector,
// not the marker, withholds a token the model streams in its thinking or in
// tool input.
func TestPassthroughRealDetectorsReadThinkingAndToolInput(t *testing.T) {
	token := syntheticGitHubToken(7)
	insp := NewGuardrailInspector("local", nil, nil)
	if v := insp.Inspect(context.Background(), "completion", "token: "+token, nil, "m", "action"); v.Action != "block" {
		t.Fatalf("control: the completion check does not block the token: %+v", v)
	}
	for _, c := range []passthroughFieldCase{
		{"anthropic/thinking_delta", "anthropic", "/v1/messages", ctSSE, sseBody(
			`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":` + jsonText("the token is "+token) + `}}`)},
		{"anthropic/input_json_delta", "anthropic", "/v1/messages", ctSSE, sseBody(
			`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":` + jsonText(`{"token":"`+token+`"}`) + `}}`)},
		{"chatshape/reasoning_content", "openai", "/v1/completions", ctJSON,
			`{"choices":[{"index":0,"message":{"content":"ok","reasoning_content":` + jsonText("the token is "+token) + `}}]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", c.contentType)
				_, _ = writeFieldBody(w, c.body)
			}))
			defer upstream.Close()
			registerRawForwardProviderDomain(t, upstream.URL, c.provider)
			allowRawForwardPrivateTargets(t)
			proxy := newTestProxy(t, &mockProvider{}, NewGuardrailInspector("local", nil, nil), "action")
			req := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(passthroughRequestBody(c.provider)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DC-Target-URL", upstream.URL)
			req.Header.Set("X-AI-Auth", "Bearer test-key")
			req.RemoteAddr = "127.0.0.1:12345"
			rec := httptest.NewRecorder()
			proxy.handlePassthrough(rec, req)
			if strings.Contains(rec.Body.String(), token) {
				t.Fatalf("the token reached the client (%d bytes)", rec.Body.Len())
			}
		})
	}
}

// TestReviewResponseFieldRows: the field rows of the s7-respfrev review
// (TestZZQrf1Fields, F01-F20 and T01-T11). Each streamed or body row
// carries the marker in one field; the completion checks must read it and
// the client must not get it. GAP-0519: Bedrock InvokeModel replies of
// every family. GAP-0520: a Gemini stream sent as a JSON array. GAP-0521:
// the legacy function_call and Responses custom tool input. GAP-0523: chat
// audio transcripts and Gemini executable code.
func TestReviewResponseFieldRows(t *testing.T) {
	M := jsonText(respFieldMarker)
	cases := []struct {
		passthroughFieldCase
		// skip names the gap of a field that stays unread; readOnly a row
		// whose read is checked but whose bytes reach the client on this
		// branch (GAP-0524: the last NDJSON line with no newline is read
		// after the stream is released; s7/stream-tail reads it in the loop).
		skip     string
		readOnly bool
	}{
		{passthroughFieldCase: passthroughFieldCase{"F01 bedrock/stream/invoke_nova_text", "bedrock", "/model/m/invoke-with-response-stream", ctEvents, eventStreamBody(t,
			"chunk", invokeChunk(`{"contentBlockDelta":{"delta":{"text":`+M+`},"contentBlockIndex":0}}`))}},
		{passthroughFieldCase: passthroughFieldCase{"F02 bedrock/stream/invoke_mistral_outputs", "bedrock", "/model/m/invoke-with-response-stream", ctEvents, eventStreamBody(t,
			"chunk", invokeChunk(`{"outputs":[{"text":`+M+`,"stop_reason":null}]}`))}},
		{passthroughFieldCase: passthroughFieldCase{"F03 bedrock/stream/invoke_cohere_text", "bedrock", "/model/m/invoke-with-response-stream", ctEvents, eventStreamBody(t,
			"chunk", invokeChunk(`{"text":`+M+`,"is_finished":false}`))}},
		{passthroughFieldCase: passthroughFieldCase{"F04 bedrock/stream/invoke_chatshape", "bedrock", "/model/m/invoke-with-response-stream", ctEvents, eventStreamBody(t,
			"chunk", invokeChunk(`{"choices":[{"index":0,"delta":{"content":`+M+`}}]}`))}},
		{passthroughFieldCase: passthroughFieldCase{"F05 bedrock/body/invoke_chatshape", "bedrock", "/model/m/invoke", ctJSON,
			`{"choices":[{"index":0,"message":{"role":"assistant","content":` + M + `}}]}`}},
		{passthroughFieldCase: passthroughFieldCase{"F06 bedrock/body/invoke_mistral_outputs", "bedrock", "/model/m/invoke", ctJSON,
			`{"outputs":[{"text":` + M + `}]}`}},
		{passthroughFieldCase: passthroughFieldCase{"F07 chatshape/stream/legacy_function_call", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"function_call":{"name":"run","arguments":` + M + `}}}]}`)}},
		{passthroughFieldCase: passthroughFieldCase{"F08 chatshape/stream/audio_transcript", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"audio":{"transcript":` + M + `}}}]}`)}},
		{passthroughFieldCase: passthroughFieldCase{"F09 chatshape/body/audio_transcript", "openai", "/v1/completions", ctJSON,
			`{"choices":[{"index":0,"message":{"content":null,"audio":{"id":"a1","transcript":` + M + `}}}]}`}},
		{passthroughFieldCase: passthroughFieldCase{"F10 gemini/body/executable_code", "gemini", "/v1beta/models/gemini-x:generateContent", ctJSON,
			`{"candidates":[{"content":{"parts":[{"executableCode":{"language":"PYTHON","code":` + M + `}}]}}]}`}},
		{passthroughFieldCase: passthroughFieldCase{"F11 gemini/stream/executable_code", "gemini", "/v1beta/models/gemini-x:streamGenerateContent", ctSSE, sseBody(
			`{"candidates":[{"content":{"parts":[{"executableCode":{"language":"PYTHON","code":` + M + `}}]}}]}`)}},
		{passthroughFieldCase: passthroughFieldCase{"F12 chatshape/stream/reasoning_details", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"reasoning_details":[{"type":"reasoning.text","text":` + M + `}]}}]}`)},
			skip: "GAP-0525 (P4): OpenRouter reasoning_details repeats delta.reasoning, which is read"},
		{passthroughFieldCase: passthroughFieldCase{"F13 responses/stream/audio_transcript", "openai", "/v1/responses", ctSSE, sseBody(
			`{"type":"response.audio.transcript.delta","delta":` + M + `}`)}},
		{passthroughFieldCase: passthroughFieldCase{"F14 responses/stream/custom_tool_input", "openai", "/v1/responses", ctSSE, sseBody(
			`{"type":"response.custom_tool_call_input.delta","output_index":1,"delta":` + M + `}`)}},
		{passthroughFieldCase: passthroughFieldCase{"F15 ollama/stream/tool_calls", "ollama", "/api/chat", ctNDJSON, ndjsonBody(
			`{"model":"llama3","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"run","arguments":{"command":`+M+`}}}]},"done":false}`,
			`{"model":"llama3","message":{"role":"assistant","content":""},"done":true}`)}},
		{passthroughFieldCase: passthroughFieldCase{"F16 chatshape/stream/crlf_nospace", "openai", "/v1/completions", ctSSE,
			"data:{\"choices\":[{\"index\":0,\"delta\":{\"content\":" + M + "}}]}\r\n\r\n"}},
		{passthroughFieldCase: passthroughFieldCase{"F17 ollama/stream/no_trailing_newline", "ollama", "/api/chat", ctNDJSON,
			`{"model":"llama3","message":{"role":"assistant","content":` + M + `},"done":true}`}, readOnly: true},
		{passthroughFieldCase: passthroughFieldCase{"F18 chatshape/body/reasoning_object", "openai", "/v1/completions", ctJSON,
			`{"choices":[{"index":0,"message":{"content":"ok","reasoning":{"text":` + M + `}}}]}`},
			skip: "GAP-0525 (P4): reasoning is read as a string; no provider sends it as an object with text"},
		{passthroughFieldCase: passthroughFieldCase{"F19 anthropic/stream/server_tool_input", "anthropic", "/v1/messages", ctSSE, sseBody(
			`{"type":"content_block_start","index":1,"content_block":{"type":"server_tool_use","id":"s1","name":"web_search","input":{}}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":`+jsonText(`{"query":"`+respFieldMarker+`"}`)+`}}`)}},
		{passthroughFieldCase: passthroughFieldCase{"F20 gemini/stream/json_array_body", "gemini", "/v1beta/models/gemini-x:streamGenerateContent", ctJSON,
			`[{"candidates":[{"content":{"parts":[{"text":"ok "}]}}]},{"candidates":[{"content":{"parts":[{"text":` + M + `}]}}]}]`}},
	}
	for _, c := range cases {
		t.Run(strings.Fields(c.name)[0], func(t *testing.T) {
			if c.skip != "" {
				t.Skipf("unread: %s", c.skip)
			}
			saw, out := runPassthroughFieldCase(t, c.passthroughFieldCase)
			if !saw {
				t.Errorf("%s: the completion checks never read the field", c.name)
			}
			if !c.readOnly && (strings.Contains(out, respFieldMarker) || (c.contentType == ctEvents && out == c.body)) {
				t.Errorf("%s: the field reached the client (%d bytes)", c.name, len(out))
			}
		})
	}

	args := jsonText(`{"command":"` + respFieldMarker + `"}`)
	bodies := []struct{ id, provider, body, skip string }{
		{"T01 anthropic/tool_use", "anthropic", `{"content":[{"type":"tool_use","id":"t","name":"run","input":{"command":` + M + `}}]}`, ""},
		{"T02 bedrock/invoke_anthropic_tool_use", "bedrock", `{"type":"message","content":[{"type":"tool_use","id":"t","name":"run","input":{"command":` + M + `}}]}`, ""},
		{"T03 bedrock/converse_tool_use", "bedrock", `{"output":{"message":{"content":[{"toolUse":{"toolUseId":"t","name":"run","input":{"command":` + M + `}}}]}}}`, ""},
		{"T04 chat/choice1_tool_calls", "openai", `{"choices":[{"index":0,"message":{"content":"ok"}},{"index":1,"message":{"tool_calls":[{"id":"c","type":"function","function":{"name":"run","arguments":` + args + `}}]}}]}`, ""},
		{"T05 chat/legacy_function_call", "openai", `{"choices":[{"index":0,"message":{"content":null,"function_call":{"name":"run","arguments":` + args + `}}}]}`, ""},
		{"T06 responses/function_call", "openai", `{"output":[{"type":"function_call","call_id":"c","name":"run","arguments":` + args + `}]}`, ""},
		{"T07 responses/custom_tool_call_input", "openai", `{"output":[{"type":"custom_tool_call","call_id":"c","name":"apply_patch","input":` + M + `}]}`, ""},
		{"T08 responses/mcp_call_arguments", "openai", `{"output":[{"type":"mcp_call","id":"m","name":"run","server_label":"s","arguments":` + args + `}]}`,
			"GAP-0525 (P4): an mcp_call runs on the provider's side"},
		{"T09 gemini/function_call", "gemini", `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"run","args":{"command":` + M + `}}}]}}]}`, ""},
		{"T10 ollama/tool_calls", "ollama", `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"run","arguments":{"command":` + M + `}}}]}}`, ""},
		{"T11 bedrock/invoke_chatshape_tool_calls", "bedrock", `{"choices":[{"index":0,"message":{"tool_calls":[{"id":"c","type":"function","function":{"name":"run","arguments":` + args + `}}]}}]}`, ""},
		{"T12 bedrock/invoke_cohere_tool_calls", "bedrock", `{"text":"","tool_calls":[{"name":"run","parameters":{"command":` + M + `}}]}`, ""},
		{"T13 gemini/json_array_function_call", "gemini", `[{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]},{"candidates":[{"content":{"parts":[{"functionCall":{"name":"run","args":{"command":` + M + `}}}]}}]}]`, ""},
	}
	for _, b := range bodies {
		t.Run(strings.Fields(b.id)[0], func(t *testing.T) {
			if b.skip != "" {
				t.Skipf("unread: %s", b.skip)
			}
			calls := extractPassthroughToolCalls([]byte(b.body), b.provider)
			text := extractPassthroughResponseContent([]byte(b.body), b.provider)
			if !strings.Contains(string(calls), respFieldMarker) && !strings.Contains(text, respFieldMarker) {
				t.Errorf("%s: never read (tool calls %s, text %q)", b.id, calls, text)
			}
			if len(calls) > 0 {
				var parsed []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				}
				if err := json.Unmarshal(calls, &parsed); err != nil || len(parsed) == 0 || parsed[0].Function.Name == "" {
					t.Errorf("%s: not in the inspectToolCalls shape: %s", b.id, calls)
				}
			}
		})
	}
}

// TestRawForwardReadsLegacyFunctionCall (GAP-0521): the raw forward path
// checks a legacy function_call as a tool call, in the body and in the
// stream, where the arguments arrive in pieces.
func TestRawForwardReadsLegacyFunctionCall(t *testing.T) {
	half1, half2 := jsonText(`{"command":"`+respFieldMarker[:9]), jsonText(respFieldMarker[9:]+`"}`)
	body := `{"choices":[{"index":0,"message":{"role":"assistant","content":null,"function_call":{"name":"run","arguments":` +
		jsonText(`{"command":"`+respFieldMarker+`"}`) + `}},"finish_reason":"function_call"}]}`
	if got := string(extractRawForwardToolCalls([]byte(body), false)); !strings.Contains(got, respFieldMarker) {
		t.Errorf("body: %s", got)
	}
	stream := sseBody(
		`{"choices":[{"index":0,"delta":{"function_call":{"name":"run","arguments":`+half1+`}}}]}`,
		`{"choices":[{"index":0,"delta":{"function_call":{"arguments":`+half2+`}},"finish_reason":"function_call"}]}`, "[DONE]")
	got := extractRawForwardToolCalls([]byte(stream), true)
	var calls []struct {
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(got, &calls); err != nil || len(calls) != 1 || calls[0].Function.Name != "run" ||
		calls[0].Function.Arguments != `{"command":"`+respFieldMarker+`"}` {
		t.Errorf("stream: %s", got)
	}
	_, deltas, finish := parseRawForwardSSEPayload(`{"choices":[{"index":0,"delta":{"function_call":{"arguments":"x"}},"finish_reason":"function_call"}]}`)
	if len(deltas) != 1 || len(finish) != 1 {
		t.Errorf("payload: deltas %d finish %v", len(deltas), finish)
	}
}
