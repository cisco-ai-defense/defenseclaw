// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAdapterRegistry_PriorityForMessagesPath pins the registry
// ordering that fixed the Anthropic-routing bug: for paths ending in
// `/messages` the anthropic adapter must win over openai-chat, because
// openai-chat's old Matches fallback would otherwise claim it first.
// This is the single dispatch rule most likely to regress silently —
// if someone re-orders buildAdapterRegistry() and bumps openai-chat
// above anthropic, Anthropic upstream will start rejecting every
// injected request with 400 invalid_request_error before the caller
// ever sees a useful log line.
func TestAdapterRegistry_PriorityForMessagesPath(t *testing.T) {
	a := adapterFor("/v1/messages", "")
	if a == nil {
		t.Fatal("no adapter matched /v1/messages")
	}
	if got := a.Name(); got != "anthropic" {
		t.Errorf("adapter for /v1/messages = %q, want %q", got, "anthropic")
	}
}

// TestAdapterRegistry_DispatchMatrix covers the rest of the path-→-
// adapter dispatch table in one table-driven test so the registry
// contract is exercised end-to-end without spinning up a proxy.
func TestAdapterRegistry_DispatchMatrix(t *testing.T) {
	cases := []struct {
		path     string
		provider string
		want     string
	}{
		{"/v1/chat/completions", "", "openai-chat"},
		{"/v1/chat/completions", "openai", "openai-chat"},
		{"/openai/v1/chat/completions", "azure", "openai-chat"},
		{"/v1/responses", "", "openai-responses"},
		{"/backend-api/codex/responses", "", "openai-responses"},
		{"/v1/messages", "", "anthropic"},
		{"/v1/models/gemini-1.5-pro:generateContent", "", "gemini"},
		{"/v1beta/models/gemini-1.5-flash:streamGenerateContent", "", "gemini"},
		{"/model/anthropic.claude-3/converse", "bedrock", "bedrock-converse"},
		{"/model/mistral.mistral-large/converse-stream", "bedrock", "bedrock-converse"},
		{"/api/chat", "", "ollama"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			a := adapterFor(c.path, c.provider)
			if a == nil {
				t.Fatalf("no adapter matched path=%q provider=%q", c.path, c.provider)
			}
			if got := a.Name(); got != c.want {
				t.Errorf("path=%q provider=%q → adapter %q, want %q", c.path, c.provider, got, c.want)
			}
		})
	}
}

// TestGeminiAdapter_InjectSystemInstruction verifies that Gemini's
// systemInstruction field is populated correctly on first-use and
// that an existing systemInstruction is merged with the notice on
// a subsequent round (that is the common case during a conversation
// where DefenseClaw may need to re-notify on every turn).
func TestGeminiAdapter_InjectSystemInstruction(t *testing.T) {
	const notice = "[DEFENSECLAW] enforcement"

	t.Run("no_existing_system_instruction", func(t *testing.T) {
		body := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
		out, err := injectSystemInstructionGemini(json.RawMessage(body), notice)
		if err != nil {
			t.Fatalf("inject error: %v", err)
		}
		// Gemini accepts `systemInstruction` as either a single
		// object (preferred) or a string. The adapter must produce
		// the object form with a parts[] array so older clients
		// that validate the richer shape still work.
		var got struct {
			SystemInstruction struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"systemInstruction"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		if len(got.SystemInstruction.Parts) == 0 {
			t.Fatal("systemInstruction.parts empty")
		}
		if !strings.Contains(got.SystemInstruction.Parts[0].Text, notice) {
			t.Errorf("notice not present in systemInstruction; got %q", got.SystemInstruction.Parts[0].Text)
		}
	})

	t.Run("merges_with_existing_string_systemInstruction", func(t *testing.T) {
		body := `{"systemInstruction":"be terse","contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
		out, err := injectSystemInstructionGemini(json.RawMessage(body), notice)
		if err != nil {
			t.Fatalf("inject error: %v", err)
		}
		// Normalized form: object with parts[] containing both the
		// notice and the caller's original string. Order puts the
		// notice first so it receives priority attention from the
		// model.
		var got map[string]json.RawMessage
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		si := string(got["systemInstruction"])
		if !strings.Contains(si, notice) {
			t.Errorf("notice missing from merged systemInstruction; got %s", si)
		}
		if !strings.Contains(si, "be terse") {
			t.Errorf("original instruction lost during merge; got %s", si)
		}
	})
}

// TestGeminiAdapter_LaunderHistory verifies that `contents[]` entries
// with role="model" whose first text part begins with the DefenseClaw
// banner are stripped, while legitimate model turns are preserved.
func TestGeminiAdapter_LaunderHistory(t *testing.T) {
	body := `{"contents":[
		{"role":"user","parts":[{"text":"hi"}]},
		{"role":"model","parts":[{"text":"[DefenseClaw] This request was blocked."}]},
		{"role":"user","parts":[{"text":"try again"}]},
		{"role":"model","parts":[{"text":"happy to help"}]}
	]}`
	out, stripped, err := launderGeminiHistory(json.RawMessage(body))
	if err != nil {
		t.Fatalf("launder error: %v", err)
	}
	if stripped != 1 {
		t.Errorf("stripped = %d, want 1", stripped)
	}
	var got struct {
		Contents []struct {
			Role  string `json:"role"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(got.Contents) != 3 {
		t.Fatalf("expected 3 contents after laundering, got %d", len(got.Contents))
	}
	for _, c := range got.Contents {
		if c.Role == "model" && len(c.Parts) > 0 && strings.HasPrefix(c.Parts[0].Text, "[DefenseClaw]") {
			t.Errorf("DefenseClaw model turn survived laundering: %+v", c)
		}
	}
}

// TestBedrockConverseAdapter_InjectSystem exercises the three shapes
// Bedrock Converse accepts for the top-level `system` field: missing,
// existing array of blocks, and (defensively) an existing string. The
// adapter must prepend a block in each case rather than overwrite or
// coerce the shape, because Bedrock's SDK validates shape strictly.
func TestBedrockConverseAdapter_InjectSystem(t *testing.T) {
	const notice = "[DEFENSECLAW] enforcement"

	t.Run("no_existing_system", func(t *testing.T) {
		body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`
		out, err := injectSystemBedrockConverse(json.RawMessage(body), notice)
		if err != nil {
			t.Fatalf("inject error: %v", err)
		}
		var got struct {
			System []struct {
				Text string `json:"text"`
			} `json:"system"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		if len(got.System) != 1 || got.System[0].Text != notice {
			t.Errorf("system = %+v, want one block with notice text", got.System)
		}
	})

	t.Run("prepends_to_existing_system_array", func(t *testing.T) {
		body := `{"system":[{"text":"be terse"}],"messages":[{"role":"user","content":[{"text":"hi"}]}]}`
		out, err := injectSystemBedrockConverse(json.RawMessage(body), notice)
		if err != nil {
			t.Fatalf("inject error: %v", err)
		}
		var got struct {
			System []struct {
				Text string `json:"text"`
			} `json:"system"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		if len(got.System) != 2 {
			t.Fatalf("system length = %d, want 2 (notice prepended + original)", len(got.System))
		}
		if got.System[0].Text != notice {
			t.Errorf("system[0] = %+v, want notice block", got.System[0])
		}
		if got.System[1].Text != "be terse" {
			t.Errorf("system[1] = %+v, want original preserved", got.System[1])
		}
	})
}

// TestBedrockConverseAdapter_LaunderHistory strips assistant turns
// whose first content block's text begins with the banner.
func TestBedrockConverseAdapter_LaunderHistory(t *testing.T) {
	body := `{"messages":[
		{"role":"user","content":[{"text":"hi"}]},
		{"role":"assistant","content":[{"text":"[DefenseClaw] blocked."}]},
		{"role":"user","content":[{"text":"try again"}]}
	]}`
	out, stripped, err := launderBedrockConverseHistory(json.RawMessage(body))
	if err != nil {
		t.Fatalf("launder error: %v", err)
	}
	if stripped != 1 {
		t.Errorf("stripped = %d, want 1", stripped)
	}
	var got struct {
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("expected 2 messages after laundering, got %d", len(got.Messages))
	}
	for _, m := range got.Messages {
		if m.Role == "assistant" && len(m.Content) > 0 && strings.HasPrefix(m.Content[0].Text, "[DefenseClaw]") {
			t.Errorf("DefenseClaw assistant turn survived laundering: %+v", m)
		}
	}
}

// TestOllamaAdapter_DispatchesToChatCompletionsShape confirms the
// ollama adapter reuses the chat-completions injector (because
// /api/chat shares the messages[] shape) and reports the same
// injection site so log consumers see consistent labels across
// OpenAI-compatible providers and native Ollama.
func TestOllamaAdapter_DispatchesToChatCompletionsShape(t *testing.T) {
	const notice = "[DEFENSECLAW] enforcement"
	body := json.RawMessage(`{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`)

	a := adapterFor("/api/chat", "")
	if a == nil {
		t.Fatal("no adapter matched /api/chat")
	}
	if a.Name() != "ollama" {
		t.Fatalf("adapter name = %q, want ollama", a.Name())
	}
	if a.InjectionSite() != "chat-completions/messages" {
		t.Errorf("injection site = %q, want chat-completions/messages", a.InjectionSite())
	}
	out, err := a.InjectSystem(body, notice)
	if err != nil {
		t.Fatalf("inject error: %v", err)
	}
	var got struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(got.Messages) < 2 || got.Messages[0].Role != "system" || got.Messages[0].Content != notice {
		t.Errorf("messages[0] = %+v, want leading system notice", got.Messages[0])
	}
}
