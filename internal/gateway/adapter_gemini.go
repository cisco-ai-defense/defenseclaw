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

// geminiAdapter handles Google's Gemini / Vertex generateContent API
// family:
//
//   - generativelanguage.googleapis.com/v1(beta)/models/<model>:generateContent
//   - generativelanguage.googleapis.com/v1(beta)/models/<model>:streamGenerateContent
//   - Vertex equivalents served on
//     <region>-aiplatform.googleapis.com/v1/projects/<p>/locations/<r>/publishers/google/models/<m>:generateContent
//
// Wire format (request):
//
//	{
//	  "systemInstruction": {"role":"system","parts":[{"text":"..."}]},
//	  "contents": [
//	    {"role":"user","parts":[{"text":"..."}]},
//	    {"role":"model","parts":[{"text":"..."}]},
//	    ...
//	  ],
//	  "generationConfig": {...}
//	}
//
// Gemini's wire format differs from the OpenAI family in three ways
// that matter for this adapter:
//
//  1. The assistant role is called "model", not "assistant". Laundering
//     must match on role=="model" (not "assistant") or DefenseClaw-
//     synthesised turns persist and keep leaking back to the LLM.
//  2. The system prompt lives in a dedicated `systemInstruction` field
//     shaped as {role,parts[]}, not a string. Coercing to string would
//     silently break Vertex which rejects a non-object here.
//  3. Text isn't a top-level field on a turn; it's inside parts[].text.
//     Multi-part turns (e.g. text + function_call) need all text parts
//     concatenated before we run the banner-prefix check.
type geminiAdapter struct{}

// Name implements FormatAdapter.
func (geminiAdapter) Name() string { return "gemini" }

// InjectionSite is the gateway.jsonl label written when InjectSystem
// succeeds. Kept distinct from anthropic/system so dashboards can slice
// by wire format.
func (geminiAdapter) InjectionSite() string { return "gemini/systemInstruction" }

// Matches selects any path whose final segment ends in
// `:generateContent` or `:streamGenerateContent`. We match by suffix
// rather than provider because Vertex and the public Gemini endpoint
// have wildly different path prefixes but the same terminal verb.
func (geminiAdapter) Matches(path, _provider string) bool {
	return strings.HasSuffix(path, ":generateContent") ||
		strings.HasSuffix(path, ":streamGenerateContent")
}

// InjectSystem merges the notification into the top-level
// `systemInstruction` field. See injectSystemInstructionGemini for the
// shape-preservation contract.
func (geminiAdapter) InjectSystem(raw json.RawMessage, content string) (json.RawMessage, error) {
	return injectSystemInstructionGemini(raw, content)
}

// LaunderHistory strips model turns whose concatenated parts[].text
// begins with the DefenseClaw banner.
func (geminiAdapter) LaunderHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	return launderGeminiHistory(raw)
}

// WriteBlockResponse emits the block in Gemini-native format.
// Streaming delegates to writeBlockedStreamGemini which emits a single
// SSE `data:` frame holding the candidates envelope — Google's client
// libraries accept this framing for streamGenerateContent.
func (geminiAdapter) WriteBlockResponse(p *GuardrailProxy, w http.ResponseWriter, _path, _model string, stream bool, msg string) {
	if stream {
		p.writeBlockedStreamGemini(w, msg)
		return
	}
	p.writeBlockedResponseGemini(w, msg)
}

// injectSystemInstructionGemini merges the notification content into
// the top-level `systemInstruction` field of a Gemini request.
// Gemini accepts either a plain-string shorthand OR the documented
// `{role,parts[]}` object shape; we always write the object shape so
// Vertex (which rejects the shorthand in some regions) keeps working.
//
// Shape preservation:
//   - absent → writes {role:"system", parts:[{text:content}]}
//   - existing object with parts[] → prepends {text:content} to parts
//   - existing string shorthand → coerces to {role:"system",
//     parts:[{text:content + \n\n + existing}]}. We upgrade the shape
//     because the server will accept either form and the object form
//     survives region differences between public Gemini and Vertex.
func injectSystemInstructionGemini(raw json.RawMessage, content string) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("proxy: inject gemini systemInstruction: unmarshal: %w", err)
	}

	notePart := map[string]string{"text": content}

	cur, has := m["systemInstruction"]
	if !has || len(cur) == 0 || string(cur) == "null" {
		obj := map[string]interface{}{
			"role":  "system",
			"parts": []map[string]string{notePart},
		}
		b, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject gemini systemInstruction: marshal new: %w", err)
		}
		m["systemInstruction"] = b
		return json.Marshal(m)
	}

	switch cur[0] {
	case '"':
		var existing string
		if err := json.Unmarshal(cur, &existing); err != nil {
			return nil, fmt.Errorf("proxy: inject gemini systemInstruction: unmarshal string: %w", err)
		}
		merged := content
		if existing != "" {
			merged = content + "\n\n" + existing
		}
		obj := map[string]interface{}{
			"role":  "system",
			"parts": []map[string]string{{"text": merged}},
		}
		b, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject gemini systemInstruction: marshal merged: %w", err)
		}
		m["systemInstruction"] = b
	case '{':
		// Prepend a parts entry so the notification wins.
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(cur, &obj); err != nil {
			return nil, fmt.Errorf("proxy: inject gemini systemInstruction: unmarshal object: %w", err)
		}
		var parts []json.RawMessage
		if pb, ok := obj["parts"]; ok && len(pb) > 0 && pb[0] == '[' {
			if err := json.Unmarshal(pb, &parts); err != nil {
				return nil, fmt.Errorf("proxy: inject gemini systemInstruction: unmarshal parts: %w", err)
			}
		}
		noteBytes, err := json.Marshal(notePart)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject gemini systemInstruction: marshal note part: %w", err)
		}
		parts = append([]json.RawMessage{noteBytes}, parts...)
		newParts, err := json.Marshal(parts)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject gemini systemInstruction: marshal parts array: %w", err)
		}
		obj["parts"] = newParts
		if _, ok := obj["role"]; !ok {
			b, err := json.Marshal("system")
			if err != nil {
				return nil, fmt.Errorf("proxy: inject gemini systemInstruction: marshal role: %w", err)
			}
			obj["role"] = b
		}
		out, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("proxy: inject gemini systemInstruction: marshal object: %w", err)
		}
		m["systemInstruction"] = out
	default:
		return nil, fmt.Errorf("proxy: inject gemini systemInstruction: unexpected shape %q", string(cur[:1]))
	}
	return json.Marshal(m)
}

// launderGeminiHistory removes model turns from the `contents` array
// whose concatenated parts[].text begins with the DefenseClaw banner.
// Gemini's assistant role is called "model"; matching on "assistant"
// would silently leak stale DefenseClaw refusals into every Vertex
// conversation that has ever been blocked.
//
// No-op when `contents` is absent or not an array (request is malformed
// and upstream will reject it anyway; better than corrupting the body).
func launderGeminiHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw, 0, fmt.Errorf("proxy: launder gemini history: unmarshal: %w", err)
	}
	contentsBytes, ok := m["contents"]
	if !ok || len(contentsBytes) == 0 || contentsBytes[0] != '[' {
		return raw, 0, nil
	}
	var turns []json.RawMessage
	if err := json.Unmarshal(contentsBytes, &turns); err != nil {
		return raw, 0, fmt.Errorf("proxy: launder gemini history: unmarshal contents: %w", err)
	}
	stripped := 0
	kept := make([]json.RawMessage, 0, len(turns))
	for _, item := range turns {
		var probe struct {
			Role  string `json:"role"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		}
		if json.Unmarshal(item, &probe) == nil && probe.Role == "model" && len(probe.Parts) > 0 {
			var b strings.Builder
			for _, p := range probe.Parts {
				b.WriteString(p.Text)
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
	newContents, err := json.Marshal(kept)
	if err != nil {
		return raw, 0, fmt.Errorf("proxy: launder gemini history: marshal contents: %w", err)
	}
	m["contents"] = newContents
	out, err := json.Marshal(m)
	if err != nil {
		return raw, 0, fmt.Errorf("proxy: launder gemini history: marshal body: %w", err)
	}
	return out, stripped, nil
}
