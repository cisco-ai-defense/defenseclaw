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

// toolResultID is the call id one tool-result message carries. Two fields are
// set only for a Responses function_call_output, the one adapter whose id form
// differs from the id OpenClaw gave the call ("<call id>|<item id>"). itemRef
// is the full id rebuilt from the request own function_call item of that call,
// and is empty unless exactly one such item names the call. callOnly is true
// when the request carries no item id for the call at all: OpenClaw replays a
// function_call without its id unless it replays the reasoning item too, so
// the result then names the call part and nothing else. items counts the
// function_call items of the request that name the call: with several, the
// result is visibly ambiguous between them, and a block of the call part is
// dropped quietly rather than left for a later replay of the result to claim.
type toolResultID struct {
	id       string
	itemRef  string
	callOnly bool
	items    int
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
	// Responses: input[] items of a tool call output carry it in call_id. That
	// is the call part of the id OpenClaw gave the call; the item part sits on
	// the function_call item of the same request, so a function_call_output is
	// tied to the full id when exactly one function_call item names its call.
	// When no item of the call carries an id, the result is the call part
	// alone (callOnly), and only when the request carries at most one item of
	// the call. Several items of one call part, named or not, leave the result
	// with neither, and it matches nothing but an id equal to its call_id.
	input := objectItems(root["input"])
	itemsOfCall := map[string][]string{}
	for _, item := range input {
		if responsesItemType(item) == "function_call" {
			callID, _ := item["call_id"].(string)
			itemID, _ := item["id"].(string)
			itemsOfCall[callID] = append(itemsOfCall[callID], itemID)
		}
	}
	for _, item := range input {
		typ := responsesItemType(item)
		callID, _ := item["call_id"].(string)
		if callID == "" || !strings.HasSuffix(typ, "_call_output") {
			continue
		}
		r := toolResultID{id: callID}
		if items := itemsOfCall[callID]; typ == "function_call_output" {
			r.items = len(items)
			named := 0
			for _, item := range items {
				if item != "" {
					named++
				}
			}
			switch {
			case len(items) == 1 && items[0] != "":
				r.itemRef = callID + "|" + items[0]
			case named == 0 && len(items) <= 1:
				r.callOnly = true
			}
		}
		ids = append(ids, r)
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

func responsesItemType(item map[string]any) string {
	typ, _ := item["type"].(string)
	return strings.ToLower(strings.TrimSpace(typ))
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
// Responses call "<call id>|<item id>" and sends back only the call id, so that
// result matches through the full id its request rebuilds (itemRef), or through
// the call part when the request names no item of the call (callOnly). A
// request that names an item of the call, or several, never matches through the
// call part, and a sibling item of the same call part is told from the block
// by the inspect-side memory, which keys calls by call part. A recorded id with
// "|" is otherwise matched only by itself. A result id is also matched when it
// is exactly the replay form of the recorded id (replayToolCallID): OpenClaw
// replays an Anthropic Messages, Chat Completions or Bedrock Converse call with
// only the letters and digits of its id, so the result carries "toolubdrk01ab"
// for the call "toolu_bdrk_01ab". Only that exact form matches, never a trimmed,
// re-cased or otherwise altered id. Two calls with one replay form share an
// inspect-side key and are ambiguous.
func (n openClawBlockNotice) isResultOf(r toolResultID) bool {
	return r.id == n.callID || r.id == replayToolCallID(n.callID) ||
		(r.itemRef != "" && r.itemRef == n.callID) ||
		(r.callOnly && noticeCallKey(n.callID) == r.id)
}
