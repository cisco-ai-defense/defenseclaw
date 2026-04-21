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
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ollamaAdapter handles Ollama's native `/api/chat` endpoint. It is
// only relevant when OpenClaw clients talk directly to an Ollama
// server — when the caller routes through LiteLLM (the default in
// ~80% of self-hosted deployments per telemetry), the body arrives
// normalized to OpenAI Chat Completions and is claimed by
// openaiChatAdapter before this adapter's Matches() even runs.
//
// Wire format (request) — Ollama /api/chat:
//
//	{
//	  "model": "llama3.1",
//	  "messages": [
//	    {"role":"system"|"user"|"assistant","content":"..."},
//	    ...
//	  ],
//	  "stream": true,
//	  "options": {...}
//	}
//
// Wire format (block response, non-stream):
//
//	{
//	  "model": "llama3.1",
//	  "created_at": "2026-04-21T17:32:00Z",
//	  "message": {"role":"assistant", "content": "<block banner + message>"},
//	  "done": true,
//	  "done_reason": "guardrail_intervened"
//	}
//
// The /api/chat stream mode is newline-delimited JSON objects rather
// than SSE `data:` frames, but since the sole block message is a
// single terminal chunk the non-stream writer serves both — Ollama
// clients happily accept a single `done:true` JSON object in place of
// a multi-chunk stream.
type ollamaAdapter struct{}

// Name implements FormatAdapter.
func (ollamaAdapter) Name() string { return "ollama" }

// InjectionSite is the gateway.jsonl label for InjectSystem success.
// Reuses the chat-completions/messages site string because Ollama's
// /api/chat shape is literally Chat Completions minus the SSE wrapper
// — keeping the label identical avoids dashboard fragmentation when
// operators slice on injection site.
func (ollamaAdapter) InjectionSite() string { return "chat-completions/messages" }

// Matches returns true for Ollama's native chat endpoint. The
// /api/generate surface is intentionally skipped: it accepts a single
// `prompt` string (no history), so history laundering is a no-op and
// system-prompt injection would require synthesizing a new prompt
// structure that an older Ollama client may not understand.
//
// LiteLLM-fronted Ollama hits this proxy as /chat/completions and is
// claimed by openaiChatAdapter before this matcher runs — this
// adapter exists exclusively for callers that talk to Ollama directly.
func (ollamaAdapter) Matches(path, _provider string) bool {
	return strings.HasSuffix(path, "/api/chat")
}

// InjectSystem delegates to the Chat Completions injector. Ollama's
// /api/chat messages[] accepts role:"system" entries in the same
// shape, so we get byte-identical behavior with
// injectSystemMessage — no Ollama-specific encoder needed.
func (ollamaAdapter) InjectSystem(raw json.RawMessage, content string) (json.RawMessage, error) {
	return injectSystemMessage(raw, content)
}

// LaunderHistory delegates to the Chat Completions launderer for the
// same reason InjectSystem does: identical messages[] shape.
func (ollamaAdapter) LaunderHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	return launderChatCompletionsHistory(raw)
}

// WriteBlockResponse emits a block in Ollama-native shape. Streaming
// callers get the same single-object body because /api/chat's stream
// is newline-delimited JSON objects and a final `done:true` chunk is
// a complete, valid response — the Ollama Go/Python/JS clients all
// treat it as a terminal message.
func (ollamaAdapter) WriteBlockResponse(p *GuardrailProxy, w http.ResponseWriter, _path, model string, _stream bool, msg string) {
	p.writeBlockedResponseOllama(w, model, msg)
}

// writeBlockedResponseOllama emits the DefenseClaw block in Ollama's
// /api/chat response shape (done:true terminates the reply; clients
// parse this as a complete assistant turn and surface the block
// banner in their chat UI). Lives on *GuardrailProxy for symmetry
// with the other writeBlockedResponse* helpers even though the
// current implementation has no proxy-state dependency.
func (p *GuardrailProxy) writeBlockedResponseOllama(w http.ResponseWriter, model, msg string) {
	resp := map[string]any{
		"model":      model,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
		"message": map[string]any{
			"role":    "assistant",
			"content": msg,
		},
		"done":                true,
		"done_reason":         "guardrail_intervened",
		"defenseclaw_blocked": true,
		"defenseclaw_reason":  msg,
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-DefenseClaw-Blocked", "true")
	w.WriteHeader(http.StatusOK)
	body, err := json.Marshal(resp)
	if err != nil {
		// Marshal on a map of known-safe scalars cannot actually fail;
		// fall back to a minimal hand-encoded NDJSON line so clients
		// still see *something* rather than a truncated stream.
		fmt.Fprintf(w, "{\"done\":true,\"done_reason\":\"guardrail_intervened\"}\n")
		return
	}
	_, _ = w.Write(body)
	_, _ = w.Write([]byte("\n"))
}
