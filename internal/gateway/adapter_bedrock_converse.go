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
)

// bedrockConverseAdapter handles Amazon Bedrock's Converse + ConverseStream
// APIs — the provider-neutral wire format that AWS added so callers do
// not have to hand-code per-family (Claude, Llama, Titan) InvokeModel
// schemas.
//
// Paths:
//
//   - /model/<modelId>/converse
//   - /model/<modelId>/converse-stream
//
// InvokeModel and InvokeWithResponseStream use per-model JSON shapes
// (Claude's Messages API, Llama's prompt/top_p, Titan's inputText, etc.)
// and are intentionally deferred — there is no single wire format for
// them to normalize onto.
//
// Wire format (request):
//
//	{
//	  "modelId": "...",
//	  "system": [{"text": "system prompt"}],
//	  "messages": [
//	    {"role":"user","content":[{"text":"..."}]},
//	    {"role":"assistant","content":[{"text":"..."}]}
//	  ],
//	  "inferenceConfig": {...}
//	}
//
// Block response format is owned by #124's proxy_bedrock_block.go,
// which this adapter delegates to — notably the streaming writer
// emits AWS `application/vnd.amazon.eventstream` binary frames that
// the AWS SDK strictly validates. Do NOT write an SSE variant here.
type bedrockConverseAdapter struct{}

// Name implements FormatAdapter.
func (bedrockConverseAdapter) Name() string { return "bedrock-converse" }

// InjectionSite is the gateway.jsonl label written when InjectSystem
// succeeds. Distinct from anthropic/system and gemini/systemInstruction
// so operators can see wire-format distribution in dashboards.
func (bedrockConverseAdapter) InjectionSite() string { return "bedrock-converse/system" }

// Matches selects /converse and /converse-stream endpoints under a
// /model/<id>/ path. We do not claim /invoke or
// /invoke-with-response-stream because those use per-model-family
// bodies that require separate adapters (deferred to a follow-up).
//
// The matcher ignores the provider argument because the Bedrock branch
// in writeBlockedPassthrough fires before the registry lookup (see
// proxy.go:writeBlockedPassthrough godoc for why) — so the `provider`
// hint is only relevant for the injectNotificationForPassthrough /
// launderInboundHistory paths, which route solely by path.
func (bedrockConverseAdapter) Matches(path, _provider string) bool {
	if !strings.Contains(path, "/model/") {
		return false
	}
	return strings.HasSuffix(path, "/"+bedrockActionConverse) ||
		strings.HasSuffix(path, "/"+bedrockActionConverseStream)
}

// InjectSystem prepends a {text: content} block to the top-level
// `system` array. See injectSystemBedrockConverse for the shape-
// preservation contract.
func (bedrockConverseAdapter) InjectSystem(raw json.RawMessage, content string) (json.RawMessage, error) {
	return injectSystemBedrockConverse(raw, content)
}

// LaunderHistory strips assistant turns from messages[] whose
// concatenated content[].text begins with the DefenseClaw banner.
// Content is always an array of {text,...} blocks in Converse
// (even for tool_use / image blocks we only care about the text blocks
// here because DefenseClaw synthesis never produces non-text content).
func (bedrockConverseAdapter) LaunderHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	return launderBedrockConverseHistory(raw)
}

// WriteBlockResponse delegates to writeBlockedPassthroughBedrock which
// inspects the path to choose between the Converse non-stream JSON
// body and the ConverseStream binary-framed eventstream. This adapter
// method exists so the FormatAdapter interface is uniform; in practice
// writeBlockedPassthrough short-circuits on provider=="bedrock" and
// calls writeBlockedPassthroughBedrock directly without consulting the
// registry. Kept here so direct adapter callers (tests, future
// registry refactors) still get the correct writer.
func (bedrockConverseAdapter) WriteBlockResponse(p *GuardrailProxy, w http.ResponseWriter, path, model string, _stream bool, msg string) {
	p.writeBlockedPassthroughBedrock(w, path, model, msg)
}

// injectSystemBedrockConverse merges the notification content into
// the top-level `system` array of a Converse request. Bedrock expects
// `system` to be an array of blocks (each typically {text:"..."}),
// and pre-2024 clients may omit the field entirely.
//
// Shape preservation:
//   - absent → writes [{text: content}]
//   - existing array → prepends {text: content}
//   - existing string (pre-Converse shorthand, not officially supported
//     by AWS but tolerated by some SDKs) → coerces to [{text: content
//   - \n\n + existing}]
//   - any other shape → error (caller logs and forwards)
func injectSystemBedrockConverse(raw json.RawMessage, content string) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("proxy: inject bedrock system: unmarshal: %w", err)
	}

	noteBlock := map[string]string{"text": content}

	cur, has := m["system"]
	if !has || len(cur) == 0 || string(cur) == "null" {
		blocks := []map[string]string{noteBlock}
		b, err := json.Marshal(blocks)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject bedrock system: marshal new: %w", err)
		}
		m["system"] = b
		return json.Marshal(m)
	}

	switch cur[0] {
	case '[':
		var blocks []json.RawMessage
		if err := json.Unmarshal(cur, &blocks); err != nil {
			return nil, fmt.Errorf("proxy: inject bedrock system: unmarshal array: %w", err)
		}
		noteBytes, err := json.Marshal(noteBlock)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject bedrock system: marshal note block: %w", err)
		}
		blocks = append([]json.RawMessage{noteBytes}, blocks...)
		out, err := json.Marshal(blocks)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject bedrock system: marshal array: %w", err)
		}
		m["system"] = out
	case '"':
		var existing string
		if err := json.Unmarshal(cur, &existing); err != nil {
			return nil, fmt.Errorf("proxy: inject bedrock system: unmarshal string: %w", err)
		}
		merged := content
		if existing != "" {
			merged = content + "\n\n" + existing
		}
		blocks := []map[string]string{{"text": merged}}
		b, err := json.Marshal(blocks)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject bedrock system: marshal coerced: %w", err)
		}
		m["system"] = b
	default:
		return nil, fmt.Errorf("proxy: inject bedrock system: unexpected shape %q", string(cur[:1]))
	}
	return json.Marshal(m)
}

// launderBedrockConverseHistory removes assistant turns from the
// `messages` array whose concatenated content[].text begins with the
// DefenseClaw banner. Converse's message shape is:
//
//	{"role":"assistant","content":[{"text":"..."}, {"toolUse":{...}}, ...]}
//
// We only inspect {text:"..."} blocks because DefenseClaw synthesis
// never emits tool_use / image blocks — any such blocks imply a real
// model turn that must not be stripped.
func launderBedrockConverseHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw, 0, fmt.Errorf("proxy: launder bedrock history: unmarshal: %w", err)
	}
	msgBytes, ok := m["messages"]
	if !ok || len(msgBytes) == 0 || msgBytes[0] != '[' {
		return raw, 0, nil
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(msgBytes, &messages); err != nil {
		return raw, 0, fmt.Errorf("proxy: launder bedrock history: unmarshal messages: %w", err)
	}
	stripped := 0
	kept := make([]json.RawMessage, 0, len(messages))
	for _, item := range messages {
		var probe struct {
			Role    string `json:"role"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if json.Unmarshal(item, &probe) == nil && probe.Role == "assistant" && len(probe.Content) > 0 {
			var b strings.Builder
			for _, c := range probe.Content {
				b.WriteString(c.Text)
			}
			if strings.HasPrefix(b.String(), defenseClawBlockBanner) {
				stripped++
				continue
			}
		}
		kept = append(kept, item)
	}
	if stripped == 0 {
		return raw, 0, nil
	}
	newMsgBytes, err := json.Marshal(kept)
	if err != nil {
		return raw, 0, fmt.Errorf("proxy: launder bedrock history: marshal messages: %w", err)
	}
	m["messages"] = newMsgBytes
	out, err := json.Marshal(m)
	if err != nil {
		return raw, 0, fmt.Errorf("proxy: launder bedrock history: marshal body: %w", err)
	}
	return out, stripped, nil
}
