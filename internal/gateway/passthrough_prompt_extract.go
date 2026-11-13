// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// The passthrough prompt check read only the user turn (substrate-1
// GAP-0196). Prompt-side text elsewhere in the body reached the provider
// uninspected: Responses instructions, system and developer turns (also
// after a user turn), tool results the agent sends back, and a body
// whose keys parse differently depending on the parser. passthroughPrompt
// reads every prompt-side text of a request body once, for every wire
// shape the passthrough serves. A body whose text it cannot read takes
// the fail mode: refused in action mode on a managed install or in the
// strict tier, otherwise forwarded with an alert that names the reason.

// uninspectablePromptFinding is the finding of a request the proxy cannot
// read.
const uninspectablePromptFinding = "PROXY-PROMPT-UNINSPECTABLE"

// passthroughPromptKeys are the top-level request fields that carry
// prompt-side text or decide the call.
var passthroughPromptKeys = map[string]bool{"model": true, "input": true, "messages": true, "instructions": true,
	"system": true, "prompt": true, "contents": true, "systemInstruction": true, "system_instruction": true, "tools": true}

// passthroughSidePrompt is the prompt-side text of a body beyond the user
// turn handlePassthrough already reads, and why the body cannot be read,
// if it cannot.
type passthroughSidePrompt struct {
	Text       string
	Unreadable string
}

// passthroughPrompt reads body. A body that is not a JSON object, or that
// names none of the prompt fields, is not a model request and has neither.
func passthroughPrompt(body []byte) passthroughSidePrompt {
	keys, ok := topLevelKeys(body)
	if !ok {
		return passthroughSidePrompt{}
	}
	prompt := false
	seen := map[string]bool{}
	for _, k := range keys {
		f := foldPromptKey(k)
		if f == "" {
			continue
		}
		prompt = prompt || (f != "model" && f != "tools")
		if f != k {
			// Another spelling of a field (Model, meſſages): some decoders
			// take it for the field and others do not.
			return passthroughSidePrompt{Unreadable: "the body spells the key " + f + " another way"}
		}
		if seen[f] {
			// Parsers disagree on which value wins (Go keeps the last and
			// matches keys case-insensitively), so the inspected value may
			// not be the one the provider reads.
			return passthroughSidePrompt{Unreadable: "the body repeats the key " + f}
		}
		seen[f] = true
	}
	if !prompt {
		return passthroughSidePrompt{}
	}
	var doc struct {
		Instructions      json.RawMessage `json:"instructions"`
		System            json.RawMessage `json:"system"`
		Input             json.RawMessage `json:"input"`
		Messages          json.RawMessage `json:"messages"`
		SystemInstruction json.RawMessage `json:"systemInstruction"`
		SystemInstrSnake  json.RawMessage `json:"system_instruction"`
		Prompt            json.RawMessage `json:"prompt"`
		Contents          json.RawMessage `json:"contents"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return passthroughSidePrompt{Unreadable: "the body is not a readable model request"}
	}
	var parts []string
	add := func(s string) {
		if strings.TrimSpace(s) != "" {
			parts = append(parts, s)
		}
	}
	add(contentText(doc.Instructions))
	add(contentText(doc.System))
	add(contentText(doc.SystemInstruction))
	add(contentText(doc.SystemInstrSnake))
	for _, list := range []json.RawMessage{doc.Input, doc.Messages} {
		var items []json.RawMessage
		if json.Unmarshal(list, &items) != nil {
			continue
		}
		for _, s := range sideTurnTexts(items) {
			add(s)
		}
	}
	side := passthroughSidePrompt{Text: strings.Join(parts, "\n")}
	if side.Text == "" && !bodyHasText(doc.Input, doc.Messages, doc.Prompt, doc.Contents) {
		side.Unreadable = "the body carries no prompt text"
	}
	return side
}

// sideTurnTexts are the prompt-side texts of a turn list (chat messages,
// Responses input items, Anthropic or Converse messages) that the user-turn
// reader skips: system and developer turns wherever they sit, and the tool
// results sent after the model's last turn (chat role tool, Responses
// function_call_output and custom_tool_call_output, Anthropic tool_result
// blocks). Older tool results are history that an earlier request already
// carried.
func sideTurnTexts(items []json.RawMessage) []string {
	type item struct {
		Type    string          `json:"type"`
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
		Output  json.RawMessage `json:"output"`
	}
	parsed := make([]item, 0, len(items))
	lastModel := -1
	for i, raw := range items {
		var it item
		_ = json.Unmarshal(raw, &it)
		parsed = append(parsed, it)
		switch {
		case it.Role == "assistant" || it.Role == "model":
			lastModel = i
		case it.Type == "function_call" || it.Type == "custom_tool_call" || it.Type == "local_shell_call" || it.Type == "reasoning":
			lastModel = i
		}
	}
	var out []string
	for i, it := range parsed {
		switch {
		case it.Role == "system" || it.Role == "developer":
			out = append(out, contentText(it.Content))
		case i < lastModel:
			continue
		case it.Role == "tool":
			out = append(out, contentText(it.Content))
		case it.Type == "function_call_output" || it.Type == "custom_tool_call_output":
			out = append(out, contentText(it.Output))
		case it.Role == "user":
			out = append(out, toolResultText(it.Content))
		}
	}
	return out
}

// toolResultText is the text of the tool_result blocks of an Anthropic user
// turn (its text blocks are the user turn itself).
func toolResultText(content json.RawMessage) string {
	var blocks []struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "tool_result" {
			parts = append(parts, contentText(b.Content))
		}
	}
	return strings.Join(parts, "\n")
}

// contentText is the text of a content value: a string, or a list of parts
// whose text sits in text, content, output or parts (also nested).
func contentText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	case '[':
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) != nil {
			return ""
		}
		var parts []string
		for _, el := range list {
			if t := contentText(el); strings.TrimSpace(t) != "" {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, "\n")
	case '{':
		var part struct {
			Text    json.RawMessage `json:"text"`
			Content json.RawMessage `json:"content"`
			Output  json.RawMessage `json:"output"`
			Parts   json.RawMessage `json:"parts"`
		}
		if json.Unmarshal(raw, &part) != nil {
			return ""
		}
		var parts []string
		for _, v := range []json.RawMessage{part.Text, part.Content, part.Output, part.Parts} {
			if t := contentText(v); strings.TrimSpace(t) != "" {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// bodyHasText reports any text in the user-side fields, so a body whose only
// text is a user turn is not called empty.
func bodyHasText(fields ...json.RawMessage) bool {
	for _, f := range fields {
		if strings.TrimSpace(contentText(f)) != "" {
			return true
		}
		var items []json.RawMessage
		if json.Unmarshal(f, &items) == nil {
			for _, it := range items {
				if strings.TrimSpace(contentText(it)) != "" {
					return true
				}
			}
		}
	}
	return false
}

// topLevelKeys lists the keys of a JSON object body in order, repeats kept.
func topLevelKeys(body []byte) ([]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, false
		}
		k, _ := t.(string)
		keys = append(keys, k)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, false
		}
	}
	return keys, true
}

// joinPromptText adds side text to the inspected text, once.
func joinPromptText(inspect, side string) string {
	switch {
	case strings.TrimSpace(side) == "" || strings.Contains(inspect, side):
		return inspect
	case strings.TrimSpace(inspect) == "":
		return side
	}
	return inspect + "\n" + side
}

// uninspectablePrompt records a request whose prompt the proxy cannot read
// and reports whether it is refused (the reply rule's fail mode,
// refuseUninspectable).
func (p *GuardrailProxy) uninspectablePrompt(ctx context.Context, label, mode, why string) bool {
	refuse := p.refuseUninspectable(ctx, mode)
	v := &ScanVerdict{Action: "alert", Severity: "MEDIUM", Scanner: "proxy",
		Reason: "the request could not be inspected: " + why, Findings: []string{uninspectablePromptFinding}}
	outcome := "forwarded with an alert"
	if refuse {
		v.Action, v.Severity, outcome = "block", "HIGH", "refused"
	}
	fmt.Fprintf(os.Stderr, "[guardrail] request not inspectable %s (%s): %s\n", label, why, outcome)
	p.recordTelemetry(ctx, "prompt", label, v, 0, mode, refuse)
	return refuse
}

// foldPromptKey is the prompt field a body key names, matched as
// encoding/json matches keys (Unicode simple folding: "meſſages" is
// "messages"), or "" for another key.
func foldPromptKey(key string) string {
	for k := range passthroughPromptKeys {
		if strings.EqualFold(key, k) {
			return k
		}
	}
	return ""
}
