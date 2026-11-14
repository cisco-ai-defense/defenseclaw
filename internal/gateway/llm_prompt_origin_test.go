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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-10:GAP-0408: on /llm only the current user turn is typed. System,
// developer and instruction fields, history, tool results and OpenClaw context
// keep the unspecified origin, so a trust finding there keeps its CRITICAL
// block in the default pack. The text is the shared fixture of
// prompt_injection_floor_test.go (floorOverridePrompt).

const (
	openClawInternalContextEnd = "<<<END_OPENCLAW_INTERNAL_CONTEXT>>>"
	llmOriginBenignAsk         = "what is on my calendar"
)

func newLLMOriginInspector(t *testing.T, strategy string) *GuardrailInspector {
	t.Helper()
	previous := liveGeneration.Load()
	liveGeneration.Store(nil)
	t.Cleanup(func() { liveGeneration.Store(previous) })
	inspector := NewGuardrailInspector("local", nil, nil)
	inspector.SetDetectionStrategy(strategy, "", "", "", false)
	return inspector
}

// inspectLLMMessages is the pre-call check handleChatCompletion runs on a
// messages request.
func inspectLLMMessages(inspector ContentInspector, messages []ChatMessage) *ScanVerdict {
	raw := promptInspectText(messages)
	return inspectPromptWithRawRecheck(context.Background(), inspector, promptInspectionText(raw), raw,
		llmTypedPromptParts(llmFieldMessages, messages), messages, "model", "action")
}

func openClawInternalContext(text string) string {
	return openClawInternalContextMarker + text + openClawInternalContextEnd
}

func openClawEnvelope(label, ask string) string {
	return "Sender (untrusted metadata):\n```json\n{\"label\":\"" + label + "\"}\n```\n\n" + ask
}

// mustChatMessages decodes a messages array as the proxy does, so content
// blocks (tool results) take the real ChatMessage parsing.
func mustChatMessages(t *testing.T, raw string) []ChatMessage {
	t.Helper()
	var messages []ChatMessage
	if err := json.Unmarshal([]byte(raw), &messages); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	return messages
}

// The four probe cases of the s7-pfdrev delta review
// (evidence/rel-1-0-10/s7/pfdrev/pfdrev_origin_scratch_test.go.txt), by case id,
// and its typed baseline. At f215f39fa2 all five alerted; only the baseline is
// text the user typed.
func TestLLMPromptOriginReviewProbes(t *testing.T) {
	p := floorOverridePrompt
	cases := []struct {
		id               string
		messages         []ChatMessage
		action, severity string
	}{
		{"typed-user-baseline", []ChatMessage{{Role: "user", Content: p}}, "alert", "HIGH"},
		{"system-only", []ChatMessage{{Role: "system", Content: p}}, "block", "CRITICAL"},
		{"developer-only", []ChatMessage{{Role: "developer", Content: p}}, "block", "CRITICAL"},
		{"openclaw-internal-context-after-prompt", []ChatMessage{
			{Role: "user", Content: "summarise my day"},
			{Role: "user", Content: openClawInternalContext(p)},
		}, "block", "CRITICAL"},
		{"openclaw-envelope-fence-body", []ChatMessage{{Role: "user", Content: openClawEnvelope(p, llmOriginBenignAsk)}}, "block", "CRITICAL"},
	}
	for _, strategy := range []string{"regex_only", "regex_judge"} {
		inspector := newLLMOriginInspector(t, strategy)
		for _, tc := range cases {
			verdict := inspectLLMMessages(inspector, tc.messages)
			if verdict == nil || verdict.Action != tc.action || verdict.Severity != tc.severity {
				t.Errorf("%s %s: verdict %+v, want %s %s", strategy, tc.id, verdict, tc.action, tc.severity)
			}
		}
	}
}

// One table maps every provider shape's fields and roles to an origin; the
// typed parts come from the messages the proxy inspects, never from a match on
// the text alone.
func TestLLMTypedPromptPartsByProviderShape(t *testing.T) {
	const typed = "the words the user typed"
	cases := []struct {
		name     string
		field    string
		messages []ChatMessage
		want     []string
	}{
		{"chat: the current turn, not history or instructions", llmFieldMessages, []ChatMessage{
			{Role: "system", Content: "be brief"},
			{Role: "user", Content: "an earlier question"},
			{Role: "assistant", Content: "an earlier answer"},
			{Role: "tool", Content: "a tool result"},
			{Role: "user", Content: typed},
			{Role: "developer", Content: "be precise"},
			{Role: "user", Content: "and a follow-up"},
		}, []string{typed, "and a follow-up"}},
		{"chat: an agent loop answers the user turn", llmFieldMessages, mustChatMessages(t, `[
			{"role":"system","content":"be brief"},
			{"role":"user","content":"`+typed+`"},
			{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"ls","arguments":"{}"}}]},
			{"role":"tool","tool_call_id":"c1","content":"a.txt"}]`), []string{typed}},
		{"chat: system only", llmFieldMessages, []ChatMessage{{Role: "system", Content: typed}}, nil},
		{"chat: developer only", llmFieldMessages, []ChatMessage{{Role: "developer", Content: typed}}, nil},
		{"chat: OpenClaw internal context", llmFieldMessages, []ChatMessage{
			{Role: "user", Content: typed},
			{Role: "user", Content: openClawInternalContext("channel context")},
		}, []string{typed}},
		{"chat: OpenClaw envelope", llmFieldMessages, []ChatMessage{{Role: "user", Content: openClawEnvelope("a label", typed)}}, []string{typed}},
		{"anthropic: a user message with a tool result is a tool turn", llmFieldMessages, mustChatMessages(t, `[
			{"role":"user","content":"`+typed+`"},
			{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"ls","input":{}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"a.txt"},{"type":"text","text":"`+typed+`"}]}]`), nil},
		{"anthropic: a bare tool result leaves the user turn typed", llmFieldMessages, mustChatMessages(t, `[
			{"role":"user","content":"`+typed+`"},
			{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"ls","input":{}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"a.txt"}]}]`), []string{typed}},
		{"bedrock: a user message with a toolResult is a tool turn", llmFieldMessages, mustChatMessages(t, `[
			{"role":"user","content":[{"text":"list my files"}]},
			{"role":"assistant","content":[{"toolUse":{"toolUseId":"t1","name":"ls","input":{}}}]},
			{"role":"user","content":[{"toolResult":{"toolUseId":"t1","content":[{"text":"a.txt"}]}},{"text":"`+typed+`"}]}]`), nil},
		{"responses: input items", llmFieldInput, mustChatMessages(t, `[
			{"role":"developer","content":"be brief"},
			{"role":"user","content":[{"type":"input_text","text":"an earlier question"}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"an earlier answer"}]},
			{"role":"user","content":[{"type":"input_text","text":"`+typed+`"}]}]`), []string{typed}},
		{"gemini: contents", llmFieldContents, []ChatMessage{
			{Role: "user", Content: "hello"},
			{Role: "assistant", Content: "hi"},
			{Role: "user", Content: typed},
		}, []string{typed}},
		{"a field that is not a message list", llmFieldSystem, []ChatMessage{{Role: "user", Content: typed}}, nil},
	}
	for _, tc := range cases {
		if got := llmTypedPromptParts(tc.field, tc.messages); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: typed parts %q, want %q", tc.name, got, tc.want)
		}
	}
	for field, want := range map[string][]string{
		llmFieldInput:             {typed},
		llmFieldPrompt:            {typed},
		llmFieldSystem:            nil,
		llmFieldInstructions:      nil,
		llmFieldSystemInstruction: nil,
	} {
		if got := llmTypedPromptField(field, typed); !reflect.DeepEqual(got, want) {
			t.Errorf("top-level %s: typed parts %q, want %q", field, got, want)
		}
	}
}

// A finding takes the ceiling only when the typed text alone produces it.
func TestScanAttributedContentRulesCapsOnlyTypedText(t *testing.T) {
	generation := userTypedTrustGeneration(t, "default")
	p := floorOverridePrompt
	for _, tc := range []struct {
		name     string
		content  string
		typed    []string
		severity string
	}{
		{"typed text only", p, []string{p}, "HIGH"},
		{"typed text after an instruction", "be brief\n" + p, []string{p}, "HIGH"},
		{"the instruction holds it", p + "\n" + llmOriginBenignAsk, []string{llmOriginBenignAsk}, "CRITICAL"},
		{"both hold it", p + "\n" + p, []string{p}, "CRITICAL"},
		{"no typed text", p, nil, "CRITICAL"},
		{"typed text not in the content", p, []string{llmOriginBenignAsk}, "CRITICAL"},
	} {
		finding := findingByRule(scanAttributedContentRules(generation, tc.content, tc.typed), "TRUST-IGNORE-PREVIOUS")
		if finding == nil {
			t.Fatalf("%s: TRUST-IGNORE-PREVIOUS did not match", tc.name)
		}
		if finding.Severity != tc.severity {
			t.Errorf("%s: severity %s, want %s", tc.name, finding.Severity, tc.severity)
		}
	}
}

// llmOriginPassthrough sends bodies through handlePassthrough to a counting
// upstream and reports whether each one was forwarded (not blocked).
func llmOriginPassthrough(t *testing.T, proxy *GuardrailProxy) func(path string, body map[string]any) bool {
	t.Helper()
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	original := providerDomains
	providerDomains = append(append(providerDomains[:0:0], providerDomains...), struct {
		domain string
		name   string
	}{target.Hostname(), "anthropic"})
	t.Cleanup(func() { providerDomains = original })
	return func(path string, body map[string]any) bool {
		before := hits.Load()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(mustJSON(t, body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DC-Target-URL", upstream.URL)
		req.Header.Set("X-AI-Auth", "Bearer inert-test")
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, req)
		return hits.Load() > before
	}
}

// Every provider shape on /llm, with several messages and roles: only the
// current user turn alerts and is forwarded; the same text in a system,
// developer or instruction field, in a tool result carried by a user message,
// or in OpenClaw context keeps its CRITICAL block in the default pack.
func TestLLMPromptOriginPerProviderShape(t *testing.T) {
	p := floorOverridePrompt
	toolUse := []map[string]any{{"type": "tool_use", "id": "t1", "name": "ls", "input": map[string]any{}}}

	t.Run("openai-chat", func(t *testing.T) {
		chatTurn := func(role, content string) map[string]any { return map[string]any{"role": role, "content": content} }
		for _, tc := range []struct {
			name      string
			messages  []map[string]any
			forwarded bool
		}{
			{"user turn after system, developer and history", []map[string]any{
				chatTurn("system", "be brief"), chatTurn("user", "an earlier question"), chatTurn("assistant", "an earlier answer"),
				chatTurn("developer", "be precise"), chatTurn("user", p),
			}, true},
			{"agent loop on the user turn", []map[string]any{
				chatTurn("user", p),
				{"role": "assistant", "content": nil, "tool_calls": []map[string]any{{"id": "c1", "type": "function", "function": map[string]any{"name": "ls", "arguments": "{}"}}}},
				{"role": "tool", "tool_call_id": "c1", "content": "a.txt"},
			}, true},
			{"system only", []map[string]any{chatTurn("system", p)}, false},
			{"developer only", []map[string]any{chatTurn("developer", p)}, false},
			{"OpenClaw internal context", []map[string]any{chatTurn("system", "be brief"), chatTurn("user", "summarise my day"), chatTurn("user", openClawInternalContext(p))}, false},
			{"OpenClaw envelope fence", []map[string]any{chatTurn("user", openClawEnvelope(p, llmOriginBenignAsk))}, false},
		} {
			proxy := newTestProxy(t, &mockProvider{}, newLLMOriginInspector(t, "regex_only"), "action")
			rec := postChat(t, proxy, mustJSON(t, map[string]any{"model": "gpt-4", "messages": tc.messages}))
			var resp ChatResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("%s: decode: %v (%s)", tc.name, err, rec.Body.String())
			}
			if forwarded := resp.ID != "chatcmpl-blocked"; forwarded != tc.forwarded {
				t.Errorf("%s: forwarded %v, want %v", tc.name, forwarded, tc.forwarded)
			}
		}
	})

	proxy := newTestProxy(t, &mockProvider{}, newLLMOriginInspector(t, "regex_only"), "action")
	send := llmOriginPassthrough(t, proxy)
	for _, tc := range []struct {
		shape, name, path string
		body              map[string]any
		forwarded         bool
	}{
		{"anthropic", "user turn after system and history", "/v1/messages", map[string]any{
			"system": "be brief",
			"messages": []map[string]any{
				{"role": "user", "content": "an earlier question"}, {"role": "assistant", "content": "an earlier answer"}, {"role": "user", "content": p},
			},
		}, true},
		{"anthropic", "agent loop on the user turn", "/v1/messages", map[string]any{"messages": []map[string]any{
			{"role": "user", "content": p}, {"role": "assistant", "content": toolUse},
			{"role": "user", "content": []map[string]any{{"type": "tool_result", "tool_use_id": "t1", "content": "a.txt"}}},
		}}, true},
		{"anthropic", "system only", "/v1/messages", map[string]any{"system": p, "messages": []map[string]any{}}, false},
		{"anthropic", "text beside a tool result", "/v1/messages", map[string]any{"messages": []map[string]any{
			{"role": "user", "content": "list my files"}, {"role": "assistant", "content": toolUse},
			{"role": "user", "content": []map[string]any{{"type": "tool_result", "tool_use_id": "t1", "content": "a.txt"}, {"type": "text", "text": p}}},
		}}, false},
		{"bedrock", "user turn after system and history", "/model/m/converse", map[string]any{
			"system": []map[string]any{{"text": "be brief"}},
			"messages": []map[string]any{
				{"role": "user", "content": []map[string]any{{"text": "hello"}}},
				{"role": "assistant", "content": []map[string]any{{"text": "hi"}}},
				{"role": "user", "content": []map[string]any{{"text": p}}},
			},
		}, true},
		{"bedrock", "text beside a toolResult", "/model/m/converse", map[string]any{"messages": []map[string]any{
			{"role": "user", "content": []map[string]any{{"text": "list my files"}}},
			{"role": "assistant", "content": []map[string]any{{"toolUse": map[string]any{"toolUseId": "t1", "name": "ls", "input": map[string]any{}}}}},
			{"role": "user", "content": []map[string]any{{"toolResult": map[string]any{"toolUseId": "t1", "content": []map[string]any{{"text": "a.txt"}}}}, {"text": p}}},
		}}, false},
		{"responses", "string input", "/v1/responses", map[string]any{"instructions": "be brief", "input": p}, true},
		{"responses", "input items after developer and history", "/v1/responses", map[string]any{"input": []map[string]any{
			{"role": "developer", "content": "be brief"},
			{"role": "user", "content": []map[string]any{{"type": "input_text", "text": "an earlier question"}}},
			{"type": "message", "role": "assistant", "content": []map[string]any{{"type": "output_text", "text": "an earlier answer"}}},
			{"role": "user", "content": []map[string]any{{"type": "input_text", "text": p}}},
		}}, true},
		{"responses", "instructions only", "/v1/responses", map[string]any{"instructions": p, "input": []map[string]any{}}, false},
		{"gemini", "user turn after systemInstruction and history", "/v1beta/models/gemini-2.5-pro:generateContent", map[string]any{
			"systemInstruction": map[string]any{"parts": []map[string]any{{"text": "be brief"}}},
			"contents": []map[string]any{
				{"role": "user", "parts": []map[string]any{{"text": "hello"}}},
				{"role": "model", "parts": []map[string]any{{"text": "hi"}}},
				{"role": "user", "parts": []map[string]any{{"text": p}}},
			},
		}, true},
		{"gemini", "systemInstruction only", "/v1beta/models/gemini-2.5-pro:generateContent", map[string]any{
			"systemInstruction": map[string]any{"parts": []map[string]any{{"text": p}}},
		}, false},
		{"ollama", "prompt beside system", "/api/generate", map[string]any{"model": "llama3.2", "system": "be brief", "prompt": p}, true},
		{"ollama", "system beside a prompt", "/api/generate", map[string]any{"model": "llama3.2", "system": p, "prompt": llmOriginBenignAsk}, false},
		{"ollama", "chat turn after system and history", "/api/chat", map[string]any{"model": "llama3.2", "messages": []map[string]any{
			{"role": "system", "content": "be brief"}, {"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}, {"role": "user", "content": p},
		}}, true},
		{"ollama", "OpenClaw internal context", "/api/chat", map[string]any{"model": "llama3.2", "messages": []map[string]any{
			{"role": "user", "content": "summarise my day"}, {"role": "user", "content": openClawInternalContext(p)},
		}}, false},
	} {
		if forwarded := send(tc.path, tc.body); forwarded != tc.forwarded {
			t.Errorf("%s %s: forwarded %v, want %v", tc.shape, tc.name, forwarded, tc.forwarded)
		}
	}
}

// The generic hook: a turn-start event marks its text typed only when it came
// from a prompt field. A task, a description, a tool field or a tool result is
// not a prompt the user typed (GAP-0408 P4).
func TestGenericTurnStartWithoutPromptFieldIsNotTyped(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "cursor"
	api := &APIServer{scannerCfg: cfg}
	for _, tc := range []struct {
		field            string
		value            any
		action, severity string
	}{
		{"prompt", floorOverridePrompt, "alert", "HIGH"},
		{"tool_info", map[string]any{"user_prompt": floorOverridePrompt}, "alert", "HIGH"},
		{"task", floorOverridePrompt, "block", "CRITICAL"},
		{"description", floorOverridePrompt, "block", "CRITICAL"},
		{"custom_instructions", floorOverridePrompt, "block", "CRITICAL"},
		{"tool_info", map[string]any{"content": floorOverridePrompt}, "block", "CRITICAL"},
		{"tool_response", floorOverridePrompt, "block", "CRITICAL"},
	} {
		req := normalizeAgentHookRequest("cursor", map[string]interface{}{
			"hook_event_name": "beforeSubmitPrompt", "session_id": "turn-start-" + tc.field, tc.field: tc.value,
		})
		resp := api.evaluateAgentHook(context.Background(), req)
		if resp.Action != tc.action || resp.Severity != tc.severity {
			t.Errorf("beforeSubmitPrompt with the text in %s: action %s severity %s, want %s %s",
				tc.field, resp.Action, resp.Severity, tc.action, tc.severity)
		}
	}
}
