// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
)

// GAP-0644: a block reference counts only where the block put it, in the
// content of the blocked tool call result, read at the place each provider
// request carries that content. The same token in a user message, an
// assistant message, a system prompt, a result or call id, a tool definition
// or any other field of a model request names no result and takes no notice.
// The body is decoded first, so a JSON escape cannot hide a reference.

// toolResultTexts returns the strings, inside the content of the tool results
// of the request body, that contain sub. A body that is not a JSON object has
// no tool result.
func toolResultTexts(body []byte, sub string) []string {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	var out []string
	add := func(content any) { collectResultStrings(content, sub, &out) }

	// Chat Completions, Ollama, Anthropic Messages and Bedrock Converse:
	// messages[]. A tool or function message carries the result in content;
	// an Anthropic tool_result or Bedrock toolResult part inside the content
	// array carries it in its own content.
	for _, msg := range objectItems(root["messages"]) {
		if role, _ := msg["role"].(string); isToolRole(role) {
			add(msg["content"])
		}
		for _, part := range objectItems(msg["content"]) {
			if typ, _ := part["type"].(string); strings.EqualFold(strings.TrimSpace(typ), "tool_result") {
				add(part["content"])
			}
			if res, ok := part["toolResult"].(map[string]any); ok {
				add(res["content"])
			}
		}
	}
	// Responses: input[] items of a tool call output carry it in output.
	for _, item := range objectItems(root["input"]) {
		if typ, _ := item["type"].(string); strings.HasSuffix(strings.ToLower(strings.TrimSpace(typ)), "_call_output") {
			add(item["output"])
		}
	}
	// Gemini: contents[].parts[].functionResponse.response.
	for _, content := range objectItems(root["contents"]) {
		for _, part := range objectItems(content["parts"]) {
			for _, key := range []string{"functionResponse", "function_response"} {
				if fr, ok := part[key].(map[string]any); ok {
					add(fr["response"])
				}
			}
		}
	}
	return out
}

func isToolRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "tool", "function":
		return true
	}
	return false
}

// objectItems returns the JSON objects of a JSON array; any other value has none.
func objectItems(v any) []map[string]any {
	arr, _ := v.([]any)
	var out []map[string]any
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// collectResultStrings gathers every string beneath a tool result content
// value (a string, an array of parts, a structured response) that contains sub.
func collectResultStrings(v any, sub string, out *[]string) {
	switch x := v.(type) {
	case string:
		if strings.Contains(x, sub) {
			*out = append(*out, x)
		}
	case []any:
		for _, e := range x {
			collectResultStrings(e, sub, out)
		}
	case map[string]any:
		for _, e := range x {
			collectResultStrings(e, sub, out)
		}
	}
}
