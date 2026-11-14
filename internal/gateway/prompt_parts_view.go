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
	"sort"
	"strings"
)

// The model reads the text parts of a message as one text: two text blocks
// in a row reach it with nothing between them. The inspected text joins the
// parts with a line feed (ChatMessage.UnmarshalJSON, extractGeminiContentsText),
// and a hook or OpenClaw message whose content is a block array is scanned as
// its JSON. A literal split across two parts then matched no literal rule
// (rel-1-0-10:GAP-0465). The content rules of a prompt therefore also read its
// parts view: the inspected text with every message of two or more text parts
// as the model reads it, the parts concatenated with no separator. A rule the
// inspected text already found keeps that finding; the view adds only the
// rules it alone finds (each scan reports one finding per rule, so the union
// is by rule and profile member). The view is never longer than the text it
// is derived from, so it adds no input that a bound could cap: the existing
// bounds (internal/guardrail/bounded) see the same sizes as before.

// isContentTextBlockType reports whether a content block of type blockType is
// text the model reads: "text" (Chat Completions, Anthropic), "input_text" and
// "output_text" (OpenAI Responses), and no type (Bedrock Converse {"text"}).
func isContentTextBlockType(blockType string) bool {
	switch blockType {
	case "text", "input_text", "output_text", "":
		return true
	}
	return false
}

// partsJoinedText is the text the model reads from parts: the parts with no
// separator. It is "" for fewer than two parts, which have no seam.
func partsJoinedText(parts []string) string {
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts, "")
}

// lineFeedJoinedParts is the inspected form of parts: a line feed before each
// part that follows text (ChatMessage.UnmarshalJSON, extractGeminiContentsText).
func lineFeedJoinedParts(parts []string) string {
	var sb strings.Builder
	for _, part := range parts {
		if sb.Len() > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(part)
	}
	return sb.String()
}

// promptPartsJoinedText is content as the model reads it: each message of
// messages with two or more text parts, and each extra part list, replaced in
// content by its parts with no separator. extra are the parts of a prompt
// field that is not a message (Gemini systemInstruction), whose inspected
// form is the parts joined with a line feed. It is "" when nothing in content
// changes.
func promptPartsJoinedText(content string, messages []ChatMessage, extra [][]string) string {
	type seam struct{ inspected, joined string }
	var seams []seam
	add := func(inspected string, parts []string) {
		joined := partsJoinedText(parts)
		if inspected == "" || joined == "" || joined == inspected || len(inspected) > len(content) {
			return
		}
		// Parts that no longer make up the inspected text (a Content
		// rewritten after parsing) give no view: the view holds only text
		// the request carries.
		if lineFeedJoinedParts(parts) != inspected {
			return
		}
		seams = append(seams, seam{inspected, joined})
	}
	for _, msg := range messages {
		add(msg.Content, msg.textParts)
	}
	for _, parts := range extra {
		add(lineFeedJoinedParts(parts), parts)
	}
	if len(seams) == 0 {
		return ""
	}
	// Longest first: a message whose text holds a shorter one's must be
	// replaced before the shorter one changes it.
	sort.SliceStable(seams, func(i, j int) bool { return len(seams[i].inspected) > len(seams[j].inspected) })
	view := content
	for _, s := range seams {
		if strings.Contains(view, s.inspected) {
			view = strings.ReplaceAll(view, s.inspected, s.joined)
		}
	}
	if view == content {
		return ""
	}
	return view
}

type promptPartsViewKey struct{}

// promptPartsView is the parts view of one inspected text.
type promptPartsView struct {
	content string
	joined  string
}

type promptTextPartsKey struct{}

// withPromptTextParts records on ctx the text parts of a prompt field that is
// not a message (Gemini systemInstruction), for the parts view of the text
// inspected from it.
func withPromptTextParts(ctx context.Context, parts []string) context.Context {
	if len(parts) < 2 {
		return ctx
	}
	prior, _ := ctx.Value(promptTextPartsKey{}).([][]string)
	return context.WithValue(ctx, promptTextPartsKey{}, append(append([][]string(nil), prior...), parts))
}

// withPromptPartsView records on ctx the parts view of content, a prompt
// inspected from messages, for the content rule scans of the inspection
// (scanLocalPatternsFor, scanProxyContentRules, triagePatternsFor). Other
// directions and a content with no seam leave ctx as it is.
func withPromptPartsView(ctx context.Context, direction, content string, messages []ChatMessage) context.Context {
	if ctx == nil || !isPromptDirection(direction) || content == "" {
		return ctx
	}
	extra, _ := ctx.Value(promptTextPartsKey{}).([][]string)
	joined := promptPartsJoinedText(content, messages, extra)
	if joined == "" {
		return ctx
	}
	return context.WithValue(ctx, promptPartsViewKey{}, promptPartsView{content: content, joined: joined})
}

// promptPartsViewOf is the parts view ctx records for content, "" for none or
// for a view of another text.
func promptPartsViewOf(ctx context.Context, content string) string {
	if ctx == nil {
		return ""
	}
	view, ok := ctx.Value(promptPartsViewKey{}).(promptPartsView)
	if !ok || view.content != content {
		return ""
	}
	return view.joined
}

// jsonContentTextParts is the text parts of content that is a JSON content
// block array, as a hook prompt field or an OpenClaw session message carries
// it ([{"type":"text","text":"..."}, ...]), or an object whose "content" or
// "parts" is one. Blocks without text (images, tool calls) are skipped. It is
// nil for any other content.
func jsonContentTextParts(content string) []string {
	trimmed := strings.TrimSpace(content)
	if len(trimmed) < 2 || (trimmed[0] != '[' && trimmed[0] != '{') {
		return nil
	}
	raw := json.RawMessage(trimmed)
	if trimmed[0] == '{' {
		var holder struct {
			Content json.RawMessage `json:"content"`
			Parts   json.RawMessage `json:"parts"`
		}
		if json.Unmarshal(raw, &holder) != nil {
			return nil
		}
		raw = holder.Content
		if len(raw) == 0 || raw[0] != '[' {
			raw = holder.Parts
		}
		if len(raw) == 0 || raw[0] != '[' {
			return nil
		}
	}
	var blocks []struct {
		Type string  `json:"type"`
		Text *string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return nil
	}
	var parts []string
	for _, block := range blocks {
		if block.Text != nil && isContentTextBlockType(block.Type) {
			parts = append(parts, *block.Text)
		}
	}
	return parts
}

// jsonContentPartsJoinedText is the parts view of JSON block content
// (jsonContentTextParts): its text parts with no separator, "" for content
// with fewer than two.
func jsonContentPartsJoinedText(content string) string {
	return partsJoinedText(jsonContentTextParts(content))
}

// unionRuleFindings merges two rule scans of one message (its text and its
// parts view, or its text and its folded trust view) into one finding per
// rule ID and profile member. A key only view has is appended; a key both
// have keeps the stronger finding in base's place (strongerRuleFinding, the
// rule the profile-meet merge uses: enforceable, then severity, then confidence).
// Trust-literal context can demote a rule to LOW detection-only from its
// surroundings, so one scan can hold a demoted match where the other found
// the same rule enforceable; a first-wins merge let the weaker one decide
// (rel-1-0-10:GAP-0527). base is not modified.
func unionRuleFindings(base, view []RuleFinding) []RuleFinding {
	if len(view) == 0 {
		return base
	}
	type ruleKey struct{ profile, rule string }
	out := make([]RuleFinding, len(base), len(base)+len(view))
	copy(out, base)
	at := make(map[ruleKey]int, len(base)+len(view))
	for i, finding := range out {
		key := ruleKey{finding.profile, finding.RuleID}
		if _, ok := at[key]; !ok {
			at[key] = i
		}
	}
	for _, finding := range view {
		key := ruleKey{finding.profile, finding.RuleID}
		if i, ok := at[key]; ok {
			if strongerRuleFinding(finding, out[i]) {
				out[i] = finding
			}
			continue
		}
		at[key] = len(out)
		out = append(out, finding)
	}
	return out
}

// unionLocalPatternVerdicts is the local-pattern verdict of a text and its
// parts view (scanLocalPatternsWithActivation of both): every finding of
// either once, at the higher severity of the two and that severity's action.
// A view that adds no finding name still raises the severity: its finding
// string is the rule's, whatever strength trust-literal context left it
// (rel-1-0-10:GAP-0527). base is not modified.
func unionLocalPatternVerdicts(base, view *ScanVerdict) *ScanVerdict {
	if view == nil || len(view.Findings) == 0 {
		return base
	}
	if base == nil || len(base.Findings) == 0 {
		return view
	}
	out := *base
	out.Findings = append([]string(nil), base.Findings...)
	seen := make(map[string]bool, len(base.Findings)+len(view.Findings))
	for _, finding := range base.Findings {
		seen[finding] = true
	}
	added := false
	for _, finding := range view.Findings {
		if !seen[finding] {
			seen[finding] = true
			out.Findings = append(out.Findings, finding)
			added = true
		}
	}
	raised := severityRank[view.Severity] > severityRank[out.Severity]
	if !added && !raised {
		return base
	}
	if raised {
		out.Severity = view.Severity
	}
	out.Action = guardrailFallbackActionForSeverity(out.Severity)
	top := out.Findings
	if len(top) > 5 {
		top = top[:5]
	}
	out.Reason = "matched: " + strings.Join(top, ", ")
	return &out
}

// triagePatternsFor is triagePatterns of a guardrail inspection: the signals
// of content and of its parts view (withPromptPartsView), each once.
func triagePatternsFor(ctx context.Context, direction, content string) []TriageSignal {
	signals := triagePatterns(direction, content)
	view := promptPartsViewOf(ctx, content)
	if view == "" {
		return signals
	}
	type signalKey struct{ level, id, category, pattern string }
	seen := make(map[signalKey]bool, len(signals))
	for _, signal := range signals {
		seen[signalKey{signal.Level, signal.FindingID, signal.Category, signal.Pattern}] = true
	}
	for _, signal := range triagePatterns(direction, view) {
		key := signalKey{signal.Level, signal.FindingID, signal.Category, signal.Pattern}
		if !seen[key] {
			seen[key] = true
			signals = append(signals, signal)
		}
	}
	return signals
}

// sessionPromptLocalVerdict is the deterministic scan of an OpenClaw
// session-message prompt (EventRouter.scanInboundPrompt): content as the
// stream carried it and, for a block array, its parts view too.
func sessionPromptLocalVerdict(content string, rules *compiledRulePackCategories, patterns *localPatternsActivation) *ScanVerdict {
	verdict := scanLocalPatternsWithActivation("prompt", content, rules, patterns)
	if joined := jsonContentPartsJoinedText(content); joined != "" {
		verdict = unionLocalPatternVerdicts(verdict, scanLocalPatternsWithActivation("prompt", joined, rules, patterns))
	}
	return verdict
}
