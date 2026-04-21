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
	"net/http"
	"strings"
)

// openaiChatAdapter handles OpenAI Chat Completions (`/v1/chat/completions`
// and the many LiteLLM-fronted shapes that normalize to the same shape:
// Mistral, Groq, Cohere, DeepSeek, Perplexity, Together, xAI, self-hosted
// vLLM, Ollama when routed through LiteLLM).
//
// This is the registry's catch-all: it must be last in buildAdapterRegistry
// so more specific adapters (Anthropic, Gemini, Bedrock, Ollama native)
// claim their traffic first.
//
// Wire format (request):
//
//	{
//	  "model": "...",
//	  "messages": [
//	    {"role": "system"|"user"|"assistant", "content": "..."},
//	    ...
//	  ]
//	}
//
// Wire format (block response): OpenAI Chat Completions JSON shape, or
// an SSE stream of `chat.completion.chunk` events for stream=true.
type openaiChatAdapter struct{}

// Name implements FormatAdapter.
func (openaiChatAdapter) Name() string { return "openai-chat" }

// InjectionSite returns the stable label written to gateway.jsonl so
// downstream dashboards (and TestInjectNotificationForPassthrough_Dispatch)
// don't break when we refactor adapter internals.
func (openaiChatAdapter) InjectionSite() string { return "chat-completions/messages" }

// Matches returns true for any path ending in /chat/completions.
//
// Prior to Phase 2 this adapter also matched /messages as a fallback
// for Anthropic traffic — that was a bug because Anthropic rejects
// role:"system" entries inside messages[] (system prompts must go in
// the top-level `system` field). The dedicated anthropicAdapter is now
// registered above this one in buildAdapterRegistry and claims
// /messages with the correct wire format.
func (openaiChatAdapter) Matches(path, _provider string) bool {
	return strings.HasSuffix(path, "/chat/completions")
}

// InjectSystem prepends a {role:"system",content:...} entry to the
// messages[] array. Delegates to the existing injectSystemMessage helper
// so regression tests in proxy_test.go stay byte-identical.
func (openaiChatAdapter) InjectSystem(raw json.RawMessage, content string) (json.RawMessage, error) {
	return injectSystemMessage(raw, content)
}

// LaunderHistory strips prior DefenseClaw-generated assistant turns from
// messages[]. Delegates to launderChatCompletionsHistory.
func (openaiChatAdapter) LaunderHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	return launderChatCompletionsHistory(raw)
}

// WriteBlockResponse writes an OpenAI Chat Completions–shaped block
// envelope. Streams emit a single chat.completion.chunk SSE; non-stream
// returns the JSON envelope.
func (openaiChatAdapter) WriteBlockResponse(p *GuardrailProxy, w http.ResponseWriter, _path, model string, stream bool, msg string) {
	if stream {
		p.writeBlockedStream(w, model, msg)
		return
	}
	p.writeBlockedResponse(w, model, msg)
}
