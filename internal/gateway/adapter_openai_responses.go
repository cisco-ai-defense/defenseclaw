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

// openaiResponsesAdapter handles the OpenAI Responses API
// (`/v1/responses`, `/openai/v1/responses`, ChatGPT's
// `/backend-api/codex/responses`, and compatible forks). It is the
// native wire format for openai-codex/gpt-5.x and for any client using
// the Responses SDK.
//
// Wire format (request):
//
//	{
//	  "model": "...",
//	  "instructions": "optional system prompt (string)",
//	  "input": [
//	    {"type":"message", "role":"user"|"assistant", "id":"msg_...",
//	     "content":[{"type":"input_text"|"output_text", "text":"..."}]},
//	    ...
//	  ]
//	}
//
// System-prompt slot: `instructions` (top-level string). We DO NOT
// prepend a message item into `input[]` because the API rejects
// assistant items whose IDs don't start with `msg_` and because
// system-ness isn't expressible in `input[]` today. See also
// injectSystemMessageForResponsesAPI in proxy.go for the reasoning.
type openaiResponsesAdapter struct{}

// Name implements FormatAdapter.
func (openaiResponsesAdapter) Name() string { return "openai-responses" }

// InjectionSite returns the stable label written to gateway.jsonl (and
// asserted by TestInjectNotificationForPassthrough_Dispatch). Kept
// byte-identical to the pre-registry behavior.
func (openaiResponsesAdapter) InjectionSite() string { return "responses-api/instructions" }

// Matches returns true for any path ending in /responses. The matcher
// intentionally ignores provider because ChatGPT's /backend-api/codex
// surface doesn't advertise provider=openai to us.
func (openaiResponsesAdapter) Matches(path, _provider string) bool {
	return strings.HasSuffix(path, "/responses")
}

// InjectSystem merges the notification content into the `instructions`
// field. Delegates to injectSystemMessageForResponsesAPI.
func (openaiResponsesAdapter) InjectSystem(raw json.RawMessage, content string) (json.RawMessage, error) {
	return injectSystemMessageForResponsesAPI(raw, content)
}

// LaunderHistory strips DefenseClaw-synthesised assistant items from
// `input[]` (matched by `msg_blocked` id prefix and/or the
// `[DefenseClaw]` content banner). Delegates to launderResponsesHistory.
func (openaiResponsesAdapter) LaunderHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	return launderResponsesHistory(raw)
}

// WriteBlockResponse writes a Responses-API-shaped block envelope.
// Streaming emits a sequence of response.* SSE events whose synthetic
// message item id starts with `msg_blocked` (required by the API).
func (openaiResponsesAdapter) WriteBlockResponse(p *GuardrailProxy, w http.ResponseWriter, _path, model string, stream bool, msg string) {
	if stream {
		p.writeBlockedStreamOpenAIResponses(w, model, msg)
		return
	}
	p.writeBlockedResponseOpenAIResponses(w, model, msg)
}
