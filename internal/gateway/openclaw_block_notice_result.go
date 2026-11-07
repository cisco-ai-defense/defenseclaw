// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
)

// GAP-0644: a block reference counts only where the block put it, in the
// result of the blocked tool call. The same token in a user message, an
// assistant message, a system prompt or any other field of a model request
// names no result and takes no notice.

// toolResultTexts returns the strings, anywhere inside a tool result of the
// request body, that contain sub. A body that is not JSON has no tool result.
func toolResultTexts(body []byte, sub string) []string {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	var out []string
	collectToolResultTexts(root, false, sub, &out)
	return out
}

func collectToolResultTexts(v any, inResult bool, sub string, out *[]string) {
	switch x := v.(type) {
	case string:
		if inResult && strings.Contains(x, sub) {
			*out = append(*out, x)
		}
	case []any:
		for _, e := range x {
			collectToolResultTexts(e, inResult, sub, out)
		}
	case map[string]any:
		inResult = inResult || isToolResultNode(x)
		for _, e := range x {
			collectToolResultTexts(e, inResult, sub, out)
		}
	}
}

// isToolResultNode names the tool result of each provider shape: a tool or
// function message (Chat Completions, Ollama), a typed output or result item
// (Responses function_call_output, Anthropic tool_result), a Bedrock
// toolResult and a Gemini functionResponse.
func isToolResultNode(m map[string]any) bool {
	if role, ok := m["role"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "tool", "function":
			return true
		}
	}
	if typ, ok := m["type"].(string); ok {
		typ = strings.ToLower(strings.TrimSpace(typ))
		if strings.HasSuffix(typ, "_output") || strings.HasSuffix(typ, "_result") {
			return true
		}
	}
	for _, key := range []string{"toolResult", "tool_result", "functionResponse", "function_response"} {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}
