// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Tool results on the /llm proxy (rel-1-0-10 GAP-0171).
//
// The proxy inspected only the user turn of a request, so a tool's output
// reached the model unread on this path (a tool-role message, an Anthropic
// tool_result block, a Responses function_call_output, a Gemini
// functionResponse). The tool results a request carries for the first time
// are the trailing ones: the outputs of the calls the model asked for in its
// last turn. Those go through the tool-result checks every hook result goes
// through (tool_result_inspect.go); earlier results were checked on the
// request that first carried them, so a conversation is not rescanned (and
// re-alerted) on every turn.

// proxyToolResult is one tool output in a model request.
type proxyToolResult struct {
	Tool    string
	Content string
}

const (
	// proxyToolResultMax bounds the outputs read from one request (a
	// parallel tool turn) and proxyToolResultMaxBytes their total text.
	proxyToolResultMax      = 32
	proxyToolResultMaxBytes = 1 << 20
)

// trailingToolResults returns the tool outputs at the end of a request, in
// order, from whichever shape carries them: chat messages (OpenAI tool-role
// messages, Anthropic user messages of tool_result blocks), Responses input
// items, or Gemini contents.
func trailingToolResults(messages []ChatMessage, input, contents json.RawMessage) []proxyToolResult {
	out := trailingChatToolResults(messages)
	if len(out) == 0 && len(bytes.TrimSpace(input)) > 0 {
		out = trailingResponsesToolResults(input)
	}
	if len(out) == 0 && len(bytes.TrimSpace(contents)) > 0 {
		out = trailingGeminiToolResults(contents)
	}
	return boundProxyToolResults(out)
}

func boundProxyToolResults(in []proxyToolResult) []proxyToolResult {
	out := make([]proxyToolResult, 0, min(len(in), proxyToolResultMax))
	total := 0
	for _, r := range in {
		if len(out) == proxyToolResultMax || total >= proxyToolResultMaxBytes {
			break
		}
		if strings.TrimSpace(r.Content) == "" {
			continue
		}
		if room := proxyToolResultMaxBytes - total; len(r.Content) > room {
			r.Content = r.Content[:room]
		}
		total += len(r.Content)
		out = append(out, r)
	}
	return out
}

func trailingChatToolResults(messages []ChatMessage) []proxyToolResult {
	var rev []proxyToolResult
walk:
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		switch m.Role {
		case "tool", "function":
			text := m.Content
			if strings.TrimSpace(text) == "" {
				text = toolResultBlockText(m.RawContent)
			}
			rev = append(rev, proxyToolResult{Tool: firstNonBlank(m.Name, m.ToolCallID), Content: text})
			continue
		case "user":
			// Anthropic Messages: the results come back as one user message
			// of tool_result blocks (optionally with text). It closes the run.
			if blocks := anthropicToolResultBlocks(m.RawContent); len(blocks) > 0 && len(rev) == 0 {
				return blocks
			}
		}
		break walk
	}
	out := make([]proxyToolResult, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out
}

// anthropicToolResultBlocks returns the tool_result blocks of an Anthropic
// user message's content array.
func anthropicToolResultBlocks(raw json.RawMessage) []proxyToolResult {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var blocks []struct {
		Type      string          `json:"type"`
		ToolUseID string          `json:"tool_use_id"`
		Content   json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return nil
	}
	var out []proxyToolResult
	for _, b := range blocks {
		if b.Type == "tool_result" {
			out = append(out, proxyToolResult{Tool: b.ToolUseID, Content: toolResultBlockText(b.Content)})
		}
	}
	return out
}

// toolResultBlockText is the text of a tool result's content: a string, or
// an array of text blocks ({"type":"text","text":...} and the Responses
// input_text / output_text forms). Other blocks (images) carry no text.
func toolResultBlockText(raw json.RawMessage) string {
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
		var parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(raw, &parts) != nil {
			return string(raw)
		}
		var b strings.Builder
		for _, p := range parts {
			if p.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return string(raw)
}

// trailingResponsesToolResults reads the trailing *_call_output items of a
// Responses API input array.
func trailingResponsesToolResults(input json.RawMessage) []proxyToolResult {
	var items []struct {
		Type   string          `json:"type"`
		CallID string          `json:"call_id"`
		Output json.RawMessage `json:"output"`
	}
	if json.Unmarshal(input, &items) != nil {
		return nil
	}
	var rev []proxyToolResult
	for i := len(items) - 1; i >= 0; i-- {
		if !strings.HasSuffix(items[i].Type, "_call_output") {
			break
		}
		rev = append(rev, proxyToolResult{Tool: items[i].CallID, Content: toolResultBlockText(items[i].Output)})
	}
	out := make([]proxyToolResult, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out
}

// trailingGeminiToolResults reads the functionResponse parts of the last
// Gemini content.
func trailingGeminiToolResults(contents json.RawMessage) []proxyToolResult {
	var turns []struct {
		Parts []struct {
			FunctionResponse *struct {
				Name     string          `json:"name"`
				Response json.RawMessage `json:"response"`
			} `json:"functionResponse"`
		} `json:"parts"`
	}
	if json.Unmarshal(contents, &turns) != nil || len(turns) == 0 {
		return nil
	}
	var out []proxyToolResult
	for _, part := range turns[len(turns)-1].Parts {
		if fr := part.FunctionResponse; fr != nil {
			out = append(out, proxyToolResult{Tool: fr.Name, Content: structuredHookContentString(json.RawMessage(fr.Response))})
		}
	}
	return out
}

func firstNonBlank(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// InspectToolResult runs the tool-result checks on one tool output for the
// proxy: the shared content rules and structural checks, then the opt-in
// judge under the completion strategy (the hook lane's opt-in for tool
// output): judge_first always, regex_judge unless the rules already block.
// Managed enterprise returns nil: AI Defense receives the conversation,
// tool messages included, on the prompt inspection.
func (g *GuardrailInspector) InspectToolResult(ctx context.Context, tool, content, model, mode string) *ScanVerdict {
	if g == nil || g.managedMode || strings.TrimSpace(content) == "" {
		return nil
	}
	findings := toolResultRuleFindings(proxyRuleGeneration(ctx), content, ruleContentScopeUntrusted, !ManagedEnterpriseActive())
	// The proxy inspects tool results for the first time in this release:
	// its findings are HIGH at most, so the default pack alerts and strict
	// refuses the model call (tool_result_inspect.go, Disposition).
	for i := range findings {
		if strings.EqualFold(findings[i].Severity, "CRITICAL") {
			findings[i].Severity = "HIGH"
		}
	}
	var local *ScanVerdict
	if len(findings) > 0 {
		sev := HighestSeverity(findings)
		ids := make([]string, 0, len(findings))
		for _, f := range findings {
			ids = append(ids, f.RuleID+":"+f.Title)
		}
		top := ids
		if len(top) > 5 {
			top = top[:5]
		}
		local = &ScanVerdict{
			Action:         guardrailFallbackActionForSeverity(sev),
			Severity:       sev,
			Reason:         "matched: " + strings.Join(top, ", "),
			Findings:       ids,
			Scanner:        "local-pattern",
			ScannerSources: []string{"local-pattern"},
		}
	}
	merged := local
	strategy := g.effectiveStrategy("completion")
	if strategy == "judge_first" || (strategy == "regex_judge" && (local == nil || local.Action != guardrailActionBlock)) {
		if judge := g.requestJudge(ctx); judge != nil {
			judgeCtx, endJudge := g.startPhaseSpan(ctx, "judge.tool_result")
			start := time.Now()
			jv := judge.RunJudges(judgeCtx, directionToolResult, content, tool)
			if jv != nil && strings.EqualFold(jv.Severity, "CRITICAL") {
				capped := *jv
				capped.Severity = "HIGH"
				jv = &capped
			}
			endJudge(phaseAction(jv), phaseSeverity(jv), time.Since(start))
			if jv != nil && !jv.JudgeFailed && jv.Severity != "" && jv.Severity != "NONE" {
				if merged == nil {
					merged = jv
				} else {
					merged = mergeVerdicts(merged, jv)
				}
			}
		}
	}
	if merged == nil {
		return allowVerdict("local-pattern")
	}
	return g.finalize(ctx, directionToolResult, model, mode, content, merged, merged, nil)
}

// inspectProxyToolResults checks the tool outputs a request carries for the
// first time and returns the strongest verdict (nil when there is nothing to
// check or the inspector has no tool-result path). Each finding is recorded
// as a tool_result guardrail evaluation.
func (p *GuardrailProxy) inspectProxyToolResults(ctx context.Context, results []proxyToolResult, model, mode string) *ScanVerdict {
	g, ok := p.inspector.(*GuardrailInspector)
	if !ok || g == nil || len(results) == 0 {
		return nil
	}
	var strongest *ScanVerdict
	for _, r := range results {
		t0 := time.Now()
		v := g.InspectToolResult(ctx, r.Tool, r.Content, model, mode)
		if v == nil {
			continue
		}
		if v.Action == guardrailActionConfirm {
			// No approval surface on a model request: a confirm is an alert.
			v.Action = guardrailActionAlert
		}
		if v.Severity != "" && v.Severity != "NONE" {
			p.recordTelemetry(ctx, directionToolResult, model, v, time.Since(t0), mode, v.Action == guardrailActionBlock && mode == "action")
		}
		if strongest == nil || strongerGuardrailAction(strongest.Action, v.Action) != strongest.Action ||
			guardrailSeverityRank(v.Severity) > guardrailSeverityRank(strongest.Severity) {
			strongest = v
		}
	}
	return strongest
}

// proxyToolResultBlockMessage is the answer when strict refuses a model call
// over a tool output: the model never reads the output.
func proxyToolResultBlockMessage(custom, reason string) string {
	return blockMessage(custom, "tool_result", reason)
}

// enforceProxyToolResults inspects the request's new tool outputs and, when a
// verdict blocks in action mode, answers the request with the block message
// instead of calling the model. It reports whether it answered.
func (p *GuardrailProxy) enforceProxyToolResults(ctx context.Context, results []proxyToolResult, model, mode, customBlockMsg string, write func(msg string)) bool {
	v := p.inspectProxyToolResults(ctx, results, model, mode)
	if v == nil || v.Action != guardrailActionBlock || mode != "action" {
		return false
	}
	msg := proxyToolResultBlockMessage(customBlockMsg, v.Reason)
	p.enqueueBlockNotification(v, "tool_result", model)
	fmt.Fprintf(defaultLogWriter, "[guardrail] tool_result block model=%s severity=%s\n", model, v.Severity)
	write(msg)
	return true
}
