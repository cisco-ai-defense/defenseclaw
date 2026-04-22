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
	"bufio"
	"bytes"
	"encoding/json"
	"net/http/httptest"
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

// TestAdapterRegistry_FullOrder pins the complete registry order. The
// priority-for-messages-path test above only catches one specific
// misordering (anthropic vs openai-chat). This test catches any
// reorder, insertion, or deletion in buildAdapterRegistry(), so a PR
// that e.g. moves ollama above openai-chat or drops the bedrock
// adapter entirely fails the suite with a clear diff rather than
// surfacing as mysterious 400s at runtime.
//
// When intentionally adding a new adapter, update this test's want
// slice in the SAME commit as the buildAdapterRegistry change — that
// paired diff is the review gate that makes sure adapter priority is
// a considered decision rather than an alphabetical accident.
func TestAdapterRegistry_FullOrder(t *testing.T) {
	got := make([]string, 0, len(adapterRegistry))
	for _, a := range adapterRegistry {
		got = append(got, a.Name())
	}
	want := []string{
		"openai-responses",
		"anthropic",
		"gemini",
		"bedrock-converse",
		"ollama",
		"openai-chat", // catch-all — must stay last
	}
	if len(got) != len(want) {
		t.Fatalf("adapterRegistry length = %d, want %d\ngot : %v\nwant: %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("adapterRegistry[%d] = %q, want %q\nfull got : %v\nfull want: %v",
				i, got[i], want[i], got, want)
		}
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

// TestOllamaAdapter_BlockResponseIsValidNDJSON parses the block
// response byte-for-byte and verifies it is a single valid NDJSON
// frame carrying the shape Ollama clients expect: `done:true`,
// `done_reason`, and `message.content` = the banner. This is the
// regression test for (a) the duplicated-reason field that was
// previously in the payload and (b) the streaming UX concern that
// clients behind buffering proxies wouldn't see the frame.
func TestOllamaAdapter_BlockResponseIsValidNDJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	p := &GuardrailProxy{}
	const msg = "[DEFENSECLAW] blocked: prompt injection"
	p.writeBlockedResponseOllama(rec, "llama3.1", msg)

	// Headers — X-Accel-Buffering:no tells nginx/HAProxy to forward
	// chunks immediately. If this regresses, streaming clients behind
	// a reverse proxy will see the block with a multi-second latency.
	if got := rec.Header().Get("X-Accel-Buffering"); got != "no" {
		t.Errorf("X-Accel-Buffering = %q, want \"no\"", got)
	}
	if got := rec.Header().Get("X-DefenseClaw-Blocked"); got != "true" {
		t.Errorf("X-DefenseClaw-Blocked = %q, want \"true\"", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", got)
	}

	// Parse the body as NDJSON (one JSON object per line). A single
	// terminal frame is the current contract, but using bufio.Scanner
	// future-proofs the test if we ever split the block into a
	// partial-content chunk + terminal-done chunk.
	scanner := bufio.NewScanner(bytes.NewReader(rec.Body.Bytes()))
	var frames []map[string]any
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var frame map[string]any
		if err := json.Unmarshal(line, &frame); err != nil {
			t.Fatalf("block response line %q not valid JSON: %v", string(line), err)
		}
		frames = append(frames, frame)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected exactly 1 NDJSON frame, got %d: %v", len(frames), frames)
	}

	frame := frames[0]
	if done, _ := frame["done"].(bool); !done {
		t.Errorf("frame.done = %v, want true", frame["done"])
	}
	if dr, _ := frame["done_reason"].(string); dr != "guardrail_intervened" {
		t.Errorf("frame.done_reason = %q, want guardrail_intervened", dr)
	}
	if blocked, _ := frame["defenseclaw_blocked"].(bool); !blocked {
		t.Errorf("frame.defenseclaw_blocked = %v, want true", frame["defenseclaw_blocked"])
	}
	// Regression: defenseclaw_reason must NOT be present. It used to
	// duplicate the banner, inflating payload size and leaking an
	// internal-only field surface.
	if _, has := frame["defenseclaw_reason"]; has {
		t.Errorf("frame.defenseclaw_reason must be absent; got %v", frame["defenseclaw_reason"])
	}
	msgObj, ok := frame["message"].(map[string]any)
	if !ok {
		t.Fatalf("frame.message is not an object: %T", frame["message"])
	}
	if role, _ := msgObj["role"].(string); role != "assistant" {
		t.Errorf("frame.message.role = %q, want assistant", role)
	}
	if content, _ := msgObj["content"].(string); content != msg {
		t.Errorf("frame.message.content = %q, want %q", content, msg)
	}
}

// TestGeminiAdapter_StreamBlockWritesSingleSSEFrame covers the
// streaming block writer: Gemini's streamGenerateContent clients
// expect `data:` SSE frames whose payload is a candidates[] envelope
// identical to the non-stream shape. We assert the frame is valid
// SSE, parses as JSON, and carries finishReason=SAFETY so the client
// library closes the stream cleanly rather than hanging waiting for
// more chunks.
func TestGeminiAdapter_StreamBlockWritesSingleSSEFrame(t *testing.T) {
	rec := httptest.NewRecorder()
	p := &GuardrailProxy{}
	const msg = "[DEFENSECLAW] blocked: policy violation"
	p.writeBlockedStreamGemini(rec, msg)

	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
	if got := rec.Header().Get("X-DefenseClaw-Blocked"); got != "true" {
		t.Errorf("X-DefenseClaw-Blocked = %q, want true", got)
	}

	body := rec.Body.String()
	if !strings.HasPrefix(body, "data: ") {
		t.Fatalf("expected SSE `data:` prefix, got %q", body)
	}
	// Strip `data: ` prefix and trailing `\n\n` to recover the JSON.
	payload := strings.TrimPrefix(body, "data: ")
	payload = strings.TrimRight(payload, "\n")
	var frame struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
				Role string `json:"role"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		DefenseClawBlocked bool `json:"defenseclaw_blocked"`
	}
	if err := json.Unmarshal([]byte(payload), &frame); err != nil {
		t.Fatalf("SSE frame payload is not valid JSON (%v): %q", err, payload)
	}
	if len(frame.Candidates) != 1 {
		t.Fatalf("expected exactly 1 candidate, got %d", len(frame.Candidates))
	}
	c := frame.Candidates[0]
	if c.FinishReason != "SAFETY" {
		t.Errorf("candidate.finishReason = %q, want SAFETY", c.FinishReason)
	}
	if c.Content.Role != "model" {
		t.Errorf("candidate.content.role = %q, want model", c.Content.Role)
	}
	if len(c.Content.Parts) != 1 || c.Content.Parts[0].Text != msg {
		t.Errorf("candidate.content.parts = %+v, want single text part with banner",
			c.Content.Parts)
	}
	if !frame.DefenseClawBlocked {
		t.Error("frame.defenseclaw_blocked must be true for downstream auditability")
	}
}

// TestGeminiAdapter_LaunderHistory_FirstPartOnlyCheck pins the
// first-part-only semantics for model-turn laundering. Previously the
// code concatenated all parts[].text and prefix-matched the banner —
// meaning an authentic upstream model turn with a toolCall block
// preceding a banner-echoing text block would have been stripped.
// After the fix, only the first TEXT-carrying part is checked, and
// non-text parts are skipped.
func TestGeminiAdapter_LaunderHistory_FirstPartOnlyCheck(t *testing.T) {
	// This turn has an empty-text part (simulating a functionCall
	// wrapper) followed by an authentic text part that happens to
	// start with the banner. Under the new semantics we DO strip
	// this turn because the banner is the first text part — that is
	// the DefenseClaw emission shape. Under the OLD concat semantics
	// we would have also stripped it (the concat also starts with
	// the banner), so this case alone doesn't discriminate; include
	// it for parity.
	body := json.RawMessage(`{"contents":[
		{"role":"model","parts":[
			{"functionCall":{"name":"tool","args":{}}},
			{"text":"` + defenseClawBlockBanner + ` blocked"}
		]}
	]}`)
	out, stripped, err := launderGeminiHistory(body)
	if err != nil {
		t.Fatalf("launder error: %v", err)
	}
	if stripped != 1 {
		t.Errorf("expected 1 turn stripped, got %d", stripped)
	}
	_ = out

	// This turn exercises the FIX: first text part is authentic
	// upstream content, a LATER text part happens to start with the
	// banner (an attacker echoing it, or a model quoting audit logs).
	// The concat semantics would have stripped this turn; the fix
	// keeps it.
	body2 := json.RawMessage(`{"contents":[
		{"role":"model","parts":[
			{"text":"Here is the weather forecast."},
			{"text":"` + defenseClawBlockBanner + ` example"}
		]}
	]}`)
	_, stripped2, err := launderGeminiHistory(body2)
	if err != nil {
		t.Fatalf("launder error: %v", err)
	}
	if stripped2 != 0 {
		t.Errorf("expected 0 turns stripped when banner is NOT in first text part, got %d", stripped2)
	}
}
