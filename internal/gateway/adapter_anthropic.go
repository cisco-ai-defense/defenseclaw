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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// anthropicAdapter handles Anthropic's Messages API (typically served
// on `/v1/messages`). Anthropic rejects `role: "system"` entries inside
// the `messages[]` array — system prompts go into a dedicated top-level
// `system` field (string OR array-of-blocks). This is the only wire
// format in the registry where pushing a system message into
// `messages[]` would hard-fail with a 4xx from the upstream, so it gets
// its own adapter ahead of openai-chat in the registry.
//
// Wire format (request):
//
//	{
//	  "model": "claude-...",
//	  "system": "optional system prompt (string OR [{type:text,text:..}])",
//	  "messages": [
//	    {"role": "user"|"assistant", "content": "..." | [{"type":"text","text":"..."}]},
//	    ...
//	  ],
//	  "stream": false
//	}
//
// Wire format (block response): same JSON envelope as a Claude reply
// (content-block with text) or, for stream=true, the Anthropic SSE event
// sequence terminating in `event: message_stop`. Delegated to the
// existing writeBlockedResponseAnthropic / writeBlockedStreamAnthropic
// helpers so streaming byte-format parity with #124's golden tests is
// preserved.
type anthropicAdapter struct{}

// Name implements FormatAdapter.
func (anthropicAdapter) Name() string { return "anthropic" }

// InjectionSite is the gateway.jsonl label written when InjectSystem
// succeeds. "anthropic/system" — top-level `system` field, NOT a
// prepended messages[] entry.
func (anthropicAdapter) InjectionSite() string { return "anthropic/system" }

// Matches routes all /messages-suffixed paths here. In Phase 1 the
// openai-chat adapter also claimed /messages as a fallback, which
// pushed role:"system" into messages[] and caused Anthropic upstreams
// to reject the request. With this adapter registered ABOVE openai-chat
// in buildAdapterRegistry, /messages traffic is now routed correctly
// and that buggy fallback branch is dropped from openai-chat.
//
// We match on path rather than provider because some clients (notably
// OpenClaw's TS plugin when rewriting X-DC-Target-URL) do not set a
// provider hint — the path is the only reliable signal here.
func (anthropicAdapter) Matches(path, _provider string) bool {
	return strings.HasSuffix(path, "/messages")
}

// InjectSystem merges the notification content into the top-level
// `system` field. Preserves whatever the client sent in `system`:
//   - absent or empty string → replace with content
//   - existing string → prepend content + "\n\n" + existing
//   - existing array-of-blocks → prepend a {type:text,text:content}
//     block; Anthropic collapses them in order at eval time
//   - any other shape → error (caller falls back to log-and-forward)
//
// Prepending (rather than appending) gives the enforcement notice
// precedence over whatever the client originally asked the model.
func (anthropicAdapter) InjectSystem(raw json.RawMessage, content string) (json.RawMessage, error) {
	return injectSystemMessageAnthropic(raw, content)
}

// LaunderHistory strips prior DefenseClaw-generated assistant turns
// from messages[]. The Anthropic Messages shape is close enough to
// Chat Completions (same `messages[]` array, same role field, content
// is either a string or an array of {type,text} blocks) that
// launderChatCompletionsHistory handles it correctly today — its
// text-extraction path collects every `text` field regardless of the
// surrounding `type`, which covers Anthropic's {type:"text",text:"..."}
// block shape. We still route it through the adapter so future
// Anthropic-specific laundering (e.g. tool_use/tool_result blocks) has
// a clean place to live.
func (anthropicAdapter) LaunderHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	return launderChatCompletionsHistory(raw)
}

// WriteBlockResponse emits the block in Anthropic-native format.
// Delegates to the existing helpers (proxy.go:writeBlockedResponseAnthropic
// and writeBlockedStreamAnthropic) to keep golden-event byte parity.
//
// Streaming dispatch note: we route on the body-level `stream` flag
// rather than the URL path because Anthropic's Messages API — unlike
// Bedrock Converse — has a single endpoint (`/v1/messages`) and the
// client signals streaming via the request body. The caller parses
// that flag in handlePassthrough before invoking this writer, so by
// the time we get here `stream` is authoritative. Do NOT normalize
// this to path-based dispatch: there is no URL distinction to key on.
func (anthropicAdapter) WriteBlockResponse(p *GuardrailProxy, w http.ResponseWriter, _path, model string, stream bool, msg string) {
	if stream {
		p.writeBlockedStreamAnthropic(w, model, msg)
		return
	}
	p.writeBlockedResponseAnthropic(w, model, msg)
}

// injectSystemMessageAnthropic merges the notification content into
// the Anthropic Messages request's top-level `system` field. Lives
// in the adapter file (rather than proxy.go alongside the other
// inject helpers) because it's format-specific logic owned by the
// anthropic adapter.
//
// Anthropic accepts either a plain string OR a content-block array
// ([{type:"text", text:"..."}, ...]) for `system`. We preserve whichever
// shape the client already used and prepend the notification content.
func injectSystemMessageAnthropic(raw json.RawMessage, content string) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("proxy: inject anthropic system: unmarshal: %w", err)
	}

	cur, has := m["system"]
	// json.RawMessage preserves source whitespace, so pretty-printed
	// bodies can have leading whitespace before the shape character.
	// TrimSpace before the shape peek so `{"system" : [...]}` with a
	// leading space inside the raw bytes is still recognized.
	trimmed := bytes.TrimSpace(cur)
	if !has || len(trimmed) == 0 || string(trimmed) == "null" {
		// No existing system — write a plain string.
		b, err := json.Marshal(content)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject anthropic system: marshal string: %w", err)
		}
		m["system"] = b
		return json.Marshal(m)
	}

	switch trimmed[0] {
	case '"':
		var existing string
		if err := json.Unmarshal(cur, &existing); err != nil {
			return nil, fmt.Errorf("proxy: inject anthropic system: unmarshal string: %w", err)
		}
		merged := content
		if existing != "" {
			merged = content + "\n\n" + existing
		}
		b, err := json.Marshal(merged)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject anthropic system: marshal merged: %w", err)
		}
		m["system"] = b
	case '[':
		// Prepend a {type:"text",text:content} block so the
		// notification wins ordering. Anthropic concatenates the
		// block array's text at eval time.
		var blocks []json.RawMessage
		if err := json.Unmarshal(cur, &blocks); err != nil {
			return nil, fmt.Errorf("proxy: inject anthropic system: unmarshal blocks: %w", err)
		}
		newBlock, err := json.Marshal(map[string]string{"type": "text", "text": content})
		if err != nil {
			return nil, fmt.Errorf("proxy: inject anthropic system: marshal block: %w", err)
		}
		blocks = append([]json.RawMessage{newBlock}, blocks...)
		out, err := json.Marshal(blocks)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject anthropic system: marshal block array: %w", err)
		}
		m["system"] = out
	default:
		// Unknown shape — refuse to silently corrupt the payload.
		return nil, fmt.Errorf("proxy: inject anthropic system: unexpected system shape %q", string(trimmed[:1]))
	}
	return json.Marshal(m)
}
