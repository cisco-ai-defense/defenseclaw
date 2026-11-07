// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
)

// GAP-0644: a block notice is keyed by the call id of the blocked call and by
// nothing else. The request body is decoded, and the id is read only from the
// id field of a tool-result message at the place each provider request carries
// it. The same token in a user message, an assistant message, a system prompt,
// a tool definition, the content of any result or any other field names no
// result and takes no notice.

// toolResultIDs returns the call id of every tool-result message of the
// request body. A body that is not a JSON object has none, and a result that
// carries no id (Ollama, Gemini without ids, the legacy function role) adds
// none.
func toolResultIDs(body []byte) []string {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	var ids []string
	add := func(v any) {
		if id, _ := v.(string); id != "" {
			ids = append(ids, id)
		}
	}

	// Chat Completions, Ollama, Anthropic Messages and Bedrock Converse:
	// messages[]. A tool message carries the id in tool_call_id; an Anthropic
	// tool_result part inside the content array carries it in tool_use_id and
	// a Bedrock toolResult part in toolUseId.
	for _, msg := range objectItems(root["messages"]) {
		if role, _ := msg["role"].(string); isToolRole(role) {
			add(msg["tool_call_id"])
		}
		for _, part := range objectItems(msg["content"]) {
			if typ, _ := part["type"].(string); strings.EqualFold(strings.TrimSpace(typ), "tool_result") {
				add(part["tool_use_id"])
			}
			if res, ok := part["toolResult"].(map[string]any); ok {
				add(res["toolUseId"])
			}
		}
	}
	// Responses: input[] items of a tool call output carry it in call_id.
	for _, item := range objectItems(root["input"]) {
		if typ, _ := item["type"].(string); strings.HasSuffix(strings.ToLower(strings.TrimSpace(typ)), "_call_output") {
			add(item["call_id"])
		}
	}
	// Gemini: contents[].parts[].functionResponse.id, when the request has one.
	for _, content := range objectItems(root["contents"]) {
		for _, part := range objectItems(content["parts"]) {
			for _, key := range []string{"functionResponse", "function_response"} {
				if fr, ok := part[key].(map[string]any); ok {
					add(fr["id"])
				}
			}
		}
	}
	return ids
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

// isResultOfAny reports whether one of the result ids is the id of the call
// this notice was recorded for. OpenClaw Responses ids are "<call id>|<item
// id>" and the Responses request sends back the part before "|", so that part
// is the same id; every other difference is a different or an unknown call.
func (n openClawBlockNotice) isResultOfAny(ids []string) bool {
	head, _, _ := strings.Cut(n.callID, "|")
	for _, id := range ids {
		if id == n.callID || (head != "" && id == head) {
			return true
		}
	}
	return false
}
