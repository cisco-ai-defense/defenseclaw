// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"unicode"
)

// GAP-0644: a block reference counts only where the block put it, in the
// content of the blocked tool call result, read at the place each provider
// request carries that content, and only in the result of the blocked call.
// The same token in a user message, an assistant message, a system prompt, a
// call id, a tool definition or any other field of a model request names no
// result and takes no notice; so does a result of another call that happens
// to carry it. The body is decoded first, so a JSON escape cannot hide a
// reference.

// openClawToolResult is one tool result of a model request: the call id the
// provider carries on it (empty when the provider has none), the tool name it
// carries (empty when the provider has none), and the strings of its content
// that contain the searched text.
type openClawToolResult struct {
	id, name string
	texts    []string
}

// toolResults returns the tool results of the request body whose content
// contains sub. A body that is not a JSON object has no tool result.
func toolResults(body []byte, sub string) []openClawToolResult {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	var out []openClawToolResult
	add := func(id, name string, content any) {
		var texts []string
		collectResultStrings(content, sub, &texts)
		if len(texts) > 0 {
			out = append(out, openClawToolResult{id: strings.TrimSpace(id), name: strings.TrimSpace(name), texts: texts})
		}
	}

	// Chat Completions, Ollama, Anthropic Messages and Bedrock Converse:
	// messages[]. A tool or function message carries the result in content
	// (Chat: tool_call_id; Ollama: tool_name; legacy function role: name); an
	// Anthropic tool_result or Bedrock toolResult part inside the content array
	// carries it in its own content, with tool_use_id / toolUseId.
	for _, msg := range objectItems(root["messages"]) {
		if role, _ := msg["role"].(string); isToolRole(role) {
			name := resultString(msg["tool_name"], msg["name"])
			add(resultString(msg["tool_call_id"]), name, msg["content"])
		}
		for _, part := range objectItems(msg["content"]) {
			if typ, _ := part["type"].(string); strings.EqualFold(strings.TrimSpace(typ), "tool_result") {
				add(resultString(part["tool_use_id"]), "", part["content"])
			}
			if res, ok := part["toolResult"].(map[string]any); ok {
				add(resultString(res["toolUseId"]), "", res["content"])
			}
		}
	}
	// Responses: input[] items of a tool call output carry it in output.
	for _, item := range objectItems(root["input"]) {
		if typ, _ := item["type"].(string); strings.HasSuffix(strings.ToLower(strings.TrimSpace(typ)), "_call_output") {
			add(resultString(item["call_id"]), "", item["output"])
		}
	}
	// Gemini: contents[].parts[].functionResponse.response, with the call id
	// when the request has one, else the function name.
	for _, content := range objectItems(root["contents"]) {
		for _, part := range objectItems(content["parts"]) {
			for _, key := range []string{"functionResponse", "function_response"} {
				if fr, ok := part[key].(map[string]any); ok {
					add(resultString(fr["id"]), resultString(fr["name"]), fr["response"])
				}
			}
		}
	}
	return out
}

func resultString(vs ...any) string {
	for _, v := range vs {
		if s, _ := v.(string); strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
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

// openClawStrictIDLength is the length of the alphanumeric call ids some
// provider adapters rewrite every call id to.
const openClawStrictIDLength = 9

// openClawCallIDForms returns the ids a provider request can name for the
// call OpenClaw knows as id: the id itself, the part before "|" (OpenClaw
// Responses ids are "<call id>|<item id>"), and the rewrites provider
// adapters apply to ids (characters outside letters, digits, "_" and "-"
// replaced by "_", letters and digits only, and the nine-character form).
func openClawCallIDForms(id string) []string {
	id = strings.TrimSpace(id)
	if i := strings.Index(id, "|"); i >= 0 {
		id = id[:i]
	}
	if id == "" {
		return nil
	}
	var kept, alnum strings.Builder
	for _, r := range id {
		switch {
		case r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			kept.WriteRune(r)
			alnum.WriteRune(r)
		case r == '_' || r == '-':
			kept.WriteRune(r)
		default:
			kept.WriteByte('_')
		}
	}
	forms := []string{id, kept.String(), alnum.String()}
	if a := alnum.String(); len(a) > openClawStrictIDLength {
		forms = append(forms, a[:openClawStrictIDLength])
	}
	return forms
}

// claims reports whether the tool result is the result of the call this notice
// was issued for. The reference must be in the result (the caller searched
// for it); on top of that the result must belong to the blocked call:
//   - a result that names a call id (Chat, Responses, Anthropic, Bedrock and a
//     Gemini request that carries ids) must name the id of the blocked call,
//     in the id itself or a provider rewrite of it; a notice issued with no
//     call id never matches such a result;
//   - a result with no call id (Ollama, Gemini without ids) must name the
//     tool of the blocked call; one that names no tool matches nothing.
//
// When the result cannot be tied to the block, the notice stays unclaimed: it
// is a UX line, so showing nothing is the safe outcome.
func (n openClawBlockNotice) claims(r openClawToolResult) bool {
	if !textsContain(r.texts, n.ref) {
		return false
	}
	if r.id != "" {
		for _, f := range openClawCallIDForms(n.callID) {
			if f == r.id {
				return true
			}
		}
		return false
	}
	return r.name != "" && r.name == n.tool
}
