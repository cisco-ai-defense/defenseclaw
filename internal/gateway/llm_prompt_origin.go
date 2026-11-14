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
	"context"
	"encoding/json"
	"strings"
)

// Who wrote the text the /llm proxy inspects before a call (rel-1-0-10:GAP-0408).
// The prompt direction holds more than the user's words: system and developer
// text, top-level instruction fields, tool results that some providers carry in a
// user-role message, and OpenClaw's own context. Only the current user turn is
// typed (ruleTextOriginUserTyped); the proxy call sites pass it in
// (inspectPromptWithRawRecheck), and the content rule scan caps a trust finding
// only when that text alone produces it (scanAttributedContentRules).

// llmPromptSource is where an /llm request carries a piece of prompt text: the
// request field and, in a message list, the role of the message. A top-level
// string field has no role.
type llmPromptSource struct {
	field string
	role  string
}

// The request fields that carry prompt text, by provider request shape.
const (
	// llmFieldMessages is messages[]: OpenAI Chat Completions, Anthropic
	// Messages, Bedrock Converse and Ollama /api/chat.
	llmFieldMessages = "messages"
	// llmFieldInput is the OpenAI and Azure Responses input, a string or items.
	llmFieldInput = "input"
	// llmFieldContents is Gemini contents[]; the proxy reads role model as
	// assistant and an unset role as user.
	llmFieldContents = "contents"
	// llmFieldPrompt is the prompt of Ollama /api/generate and legacy completions.
	llmFieldPrompt = "prompt"
	// The top-level instruction fields: Anthropic and Ollama system, Responses
	// instructions, Gemini systemInstruction.
	llmFieldSystem            = "system"
	llmFieldInstructions      = "instructions"
	llmFieldSystemInstruction = "systemInstruction"
)

// llmPromptSourceOrigins is who wrote each source of /llm prompt text, for every
// provider shape. Only the user's own messages are typed. A source that is not
// in the table is not: system and developer messages, assistant, tool and model
// history, a user-role message that carries a tool result (llmToolResultBlocks),
// and the top-level system, instructions and systemInstruction fields.
var llmPromptSourceOrigins = map[llmPromptSource]ruleTextOrigin{
	{llmFieldMessages, "user"}: ruleTextOriginUserTyped,
	{llmFieldInput, "user"}:    ruleTextOriginUserTyped,
	{llmFieldInput, ""}:        ruleTextOriginUserTyped, // input as one string
	{llmFieldContents, "user"}: ruleTextOriginUserTyped,
	{llmFieldPrompt, ""}:       ruleTextOriginUserTyped,
}

// llmToolResultBlocks are the content blocks that make a user-role message a
// tool turn: Anthropic {"type":"tool_result"} and Bedrock Converse
// {"toolResult":{...}} carry a tool's output in a user message.
var llmToolResultBlocks = []string{"tool_result", "toolResult"}

// openClawInternalContextMarker opens the context message OpenClaw 2026.9
// appends after the prompt (GAP-0190). OpenClaw wrote it, not the user.
const openClawInternalContextMarker = "<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>"

// llmPromptRole is the role of msg for llmPromptSourceOrigins: "tool" for a
// message that carries a tool result, else its own role.
func llmPromptRole(msg ChatMessage) string {
	if len(msg.RawContent) == 0 || msg.RawContent[0] != '[' {
		return msg.Role
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(msg.RawContent, &blocks) != nil {
		return msg.Role
	}
	for _, block := range blocks {
		var blockType string
		if raw, ok := block["type"]; ok {
			_ = json.Unmarshal(raw, &blockType)
		}
		for _, kind := range llmToolResultBlocks {
			if _, ok := block[kind]; ok || blockType == kind {
				return "tool"
			}
		}
	}
	return msg.Role
}

// llmTypedPromptParts is the text the user typed among the messages the proxy
// inspects before a call (promptInspectMessages: the current user turn, else
// the latest user message), for a message list that came from field. A message
// is typed only by its source (llmPromptSourceOrigins); the parts come from the
// same messages as the inspected text, never from a match on the text alone.
// An OpenClaw internal-context message is not typed, and the OpenClaw metadata
// envelope of a message is not part of its typed text
// (stripOpenClawUntrustedEnvelope).
func llmTypedPromptParts(field string, messages []ChatMessage) []string {
	var parts []string
	for _, msg := range promptInspectMessages(messages) {
		if llmPromptSourceOrigins[llmPromptSource{field: field, role: llmPromptRole(msg)}] != ruleTextOriginUserTyped {
			continue
		}
		if strings.Contains(msg.Content, openClawInternalContextMarker) {
			continue
		}
		if typed := strings.TrimSpace(stripOpenClawUntrustedEnvelope(msg.Content)); typed != "" {
			parts = append(parts, typed)
		}
	}
	return parts
}

// llmTypedPromptField is the typed text of a top-level string field: all of
// text when the field is typed (llmPromptSourceOrigins), else none of it.
func llmTypedPromptField(field, text string) []string {
	if llmPromptSourceOrigins[llmPromptSource{field: field}] != ruleTextOriginUserTyped {
		return nil
	}
	if typed := strings.TrimSpace(stripOpenClawUntrustedEnvelope(text)); typed != "" {
		return []string{typed}
	}
	return nil
}

type llmTypedPromptKey struct{}

// withLLMTypedPrompt records on ctx the texts the user typed in the /llm prompt
// being inspected (llmTypedPromptParts).
func withLLMTypedPrompt(ctx context.Context, typed []string) context.Context {
	if len(typed) == 0 {
		return ctx
	}
	return context.WithValue(ctx, llmTypedPromptKey{}, typed)
}

// proxyTypedPrompt is the typed text of the /llm prompt that ctx inspects, nil
// for a completion or for a scan the proxy did not attribute.
func proxyTypedPrompt(ctx context.Context, direction string) []string {
	if ctx == nil || !isPromptDirection(direction) {
		return nil
	}
	typed, _ := ctx.Value(llmTypedPromptKey{}).([]string)
	return typed
}

// scanAttributedContentRules is scanUntrustedContentRules for content that holds
// the typed texts of a prompt among text the user did not type. A finding takes
// the user-typed ceiling (applyUserTypedTrustCeiling) only when the typed text
// alone produces it and the rest of the content does not; a finding that the
// rest produces, or that needs both, keeps its severity. Content with no typed
// text has the unspecified origin.
func scanAttributedContentRules(generation *compiledRulePackCategories, content string, typed []string) []RuleFinding {
	typedText, rest, found := splitTypedPromptText(content, typed)
	if !found {
		return scanUntrustedContentRules(generation, content, ruleTextOriginUnspecified)
	}
	if strings.TrimSpace(rest) == "" {
		return scanUntrustedContentRules(generation, content, ruleTextOriginUserTyped)
	}
	findings := scanUntrustedContentRules(generation, content, ruleTextOriginUnspecified)
	aboveCeiling := false
	for _, finding := range findings {
		if guardrailSeverityRank(finding.Severity) > guardrailSeverityRank(userTypedTrustCeiling) {
			aboveCeiling = true
			break
		}
	}
	if !aboveCeiling {
		return findings
	}
	fromRest := make(map[string]bool)
	for _, finding := range scanUntrustedContentRules(generation, rest, ruleTextOriginUnspecified) {
		fromRest[finding.RuleID] = true
	}
	fromTyped := make(map[string]string)
	for _, finding := range scanUntrustedContentRules(generation, typedText, ruleTextOriginUserTyped) {
		fromTyped[finding.RuleID] = finding.Severity
	}
	for i, finding := range findings {
		if severity, ok := fromTyped[finding.RuleID]; ok && !fromRest[finding.RuleID] {
			findings[i].Severity = severity
		}
	}
	return findings
}

// splitTypedPromptText takes each typed text out of content, last first, and
// returns the typed texts found, joined, and what is left of content.
func splitTypedPromptText(content string, typed []string) (typedText, rest string, found bool) {
	rest = content
	var parts []string
	for i := len(typed) - 1; i >= 0; i-- {
		part := typed[i]
		at := strings.LastIndex(rest, part)
		if part == "" || at < 0 {
			continue
		}
		rest = rest[:at] + "\n" + rest[at+len(part):]
		parts = append(parts, part)
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "\n"), rest, len(parts) > 0
}
