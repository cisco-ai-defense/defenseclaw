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

// toolResultID is the call id one tool-result message carries. responses is
// true only for the id of a Responses function_call_output item, the one
// adapter whose id form differs from the id OpenClaw gave the call.
type toolResultID struct {
	id        string
	responses bool
}

// toolResultIDs returns the call id of every tool-result message of the
// request body. A body that is not a JSON object has none, and a result that
// carries no id (Ollama, Gemini without ids, the legacy function role) adds
// none.
func toolResultIDs(body []byte) []toolResultID {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	var ids []toolResultID
	add := func(v any) {
		if id, _ := v.(string); id != "" {
			ids = append(ids, toolResultID{id: id})
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
			if id, _ := item["call_id"].(string); id != "" {
				ids = append(ids, toolResultID{id: id, responses: true})
			}
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

// isResultOf reports whether one result id is the id of the call this notice
// was recorded for. The id must equal the recorded id. The one provider form
// that differs is the Responses function_call_output: OpenClaw names a
// Responses call "<call id>|<item id>" and sends back only the call id, so on
// that adapter alone the part before "|" is the same call. On every other
// adapter a recorded id with "|" is matched only by itself, and a result whose
// id is only the head of it is another call.
func (n openClawBlockNotice) isResultOf(r toolResultID) bool {
	if r.id == n.callID {
		return true
	}
	if !r.responses {
		return false
	}
	head, _, found := strings.Cut(n.callID, "|")
	return found && head != "" && r.id == head
}
