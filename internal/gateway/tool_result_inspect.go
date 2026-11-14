// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The tool-result surface (rel-1-0-10 GAP-0171).
//
// Every connector's finished tool call (the PostToolUse hook of Claude Code,
// Codex and the generic agent hooks) and every tool result the /llm proxy
// forwards to a model (tool-role messages, Anthropic tool_result blocks,
// Responses function_call_output items, Gemini functionResponse parts) runs
// the same content checks, here:
//
//   - the content rules a tool's output can carry an attack in: trust-exploit
//     (prompt injection), secrets, and the enterprise-data rules except
//     contact and payment data (rules tagged contact, pci or financial: email
//     addresses, phone numbers, cards, IBANs). Those are what an inbox, a
//     contact list or a statement returns by design and alerted on ordinary
//     output (strict: 67% of benign AgentDojo tool outputs). Regulated
//     identifiers, bulk SSN/account records and operators' own rules without
//     those tags stay checked. PII in the output of named tools stays covered
//     by the sensitive-tools result inspection and the opt-in PII judge;
//   - the C2 rules (known exfil and tunnel hosts: webhook.site, ngrok, cloud
//     metadata, ...): LOW telemetry on the hook connectors, which never ran
//     them on output (on the owner's real tool outputs they alerted or blocked
//     98 times, all docs and fixtures, run s7tr-atA); the generic
//     /inspect/tool-response route, which ran every rule on output before,
//     keeps the command, path, cognitive-file and C2 rules at the tool-result
//     severity (toolResponseEndpointFindings). The call to a host is judged at
//     PreToolUse;
//   - the trust-exploit rules again on the tool-result view: string escapes
//     decoded (tool output is often JSON or YAML in which the text the model
//     reads is a quoted string) and confusables folded;
//   - the structural injection checks (tool_result_injection.go);
//   - the opt-in judge, with the tool-result injection prompt (llm_judge.go).
//
// Disposition (S7 lead decision 2026-11-13, option B in plans TOOLRESULT.md):
// no result-side block in the default pack. The call has already run; a block
// cannot undo it and on the connectors that can act on it only withholds the
// output. Every finding on this surface is HIGH at most (rules here, the judge
// in capToolResultJudgeVerdict, the structural checks): the default and
// permissive packs (block at CRITICAL) alert, strict (block at MEDIUM) blocks,
// which withholds the output where the connector can (Codex PostToolUse, Amp
// tool.result, the /llm proxy refusing the model call) and is an alert with
// would_block elsewhere (docs-site guardrail/tool-results.mdx).

const directionToolResult = "tool_result"

// isToolResultDirection reports the tool-result surface. "tool-response" is
// the generic /inspect/tool-response route's name for it.
func isToolResultDirection(direction string) bool {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case directionToolResult, "tool-response":
		return true
	}
	return false
}

// toolResultRuleFindings returns the content-rule and structural findings of
// one tool output. scanRaw false (managed enterprise) skips the raw rule scan
// as messageRuleFindings does; the view and the structural checks still run.
func toolResultRuleFindings(generation *compiledRulePackCategories, content string, scope ruleContentScope, scanRaw bool) []RuleFinding {
	return toolResultChecks(generation, content, "message", scope, scanRaw, false)
}

// toolResponseEndpointFindings is toolResultRuleFindings for the generic
// /api/v1/inspect/tool-response route (shell hooks, sandbox ingress, managed
// peers). That route ran every rule on a tool's output before 1.0.10; it
// keeps the command, sensitive-path, cognitive-file and C2 rules, at the
// tool-result severity (HIGH at most).
func toolResponseEndpointFindings(generation *compiledRulePackCategories, content, toolName string, scanRaw bool) []RuleFinding {
	return toolResultChecks(generation, content, toolName, ruleContentScopeUntrusted, scanRaw, true)
}

// toolResultDataRuleSkipped reports a contact or payment data rule, which a
// tool's output carries by design (surface comment above).
func toolResultDataRuleSkipped(tags []string) bool {
	return hasTag(tags, "contact") || hasTag(tags, "pci") || hasTag(tags, "financial")
}

func toolResultChecks(generation *compiledRulePackCategories, content, toolName string, scope ruleContentScope, scanRaw, actionRules bool) []RuleFinding {
	if scope == ruleContentScopeAll {
		scope = ruleContentScopeUntrusted
	}
	var findings, injection []RuleFinding
	if scanRaw {
		for _, f := range scanContentRulesWithOptions(generation, content, "message", scope,
			ruleScanOptions{excludeTrustExploit: true}) {
			if !toolResultDataRuleSkipped(f.Tags) {
				findings = append(findings, f)
			}
		}
		injection = scanContentRulesWithOptions(generation, content, "message", scope,
			ruleScanOptions{onlyCategory: "trust-exploit"})
		switch {
		case scope == ruleContentScopeSource:
		case actionRules:
			for _, category := range []string{"command", "sensitive-path", "cognitive-file", "c2"} {
				findings = append(findings, scanContentRulesWithOptions(generation, content, toolName, ruleContentScopeAll,
					ruleScanOptions{onlyCategory: category})...)
			}
		default:
			// C2 is an action category, which a content scope leaves out; on a
			// hook connector's tool output it runs as telemetry.
			for _, f := range scanContentRulesWithOptions(generation, content, "message", ruleContentScopeAll,
				ruleScanOptions{onlyCategory: "c2"}) {
				f.Severity = "LOW"
				findings = append(findings, f)
			}
		}
	}
	seen := make(map[string]bool, len(injection))
	for _, f := range injection {
		seen[f.RuleID] = true
	}
	view := toolResultView(content)
	if view != content {
		for _, f := range scanContentRulesWithOptions(generation, view, "message", scope,
			ruleScanOptions{onlyCategory: "trust-exploit"}) {
			if !seen[f.RuleID] {
				seen[f.RuleID] = true
				injection = append(injection, f)
			}
		}
	}
	for _, f := range toolResultInjectionFindings(view) {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		if scope == ruleContentScopeSource {
			// Verified workspace source (a test fixture, a rule file) is
			// telemetry, as for every other rule (scanContentRulesWithOptions).
			f.Severity = "LOW"
			f.enforcement = findingEnforcementDetectionOnly
		}
		injection = append(injection, f)
	}
	out := append(findings, injection...)
	for i := range out {
		if strings.EqualFold(out[i].Severity, "CRITICAL") {
			out[i].Severity = "HIGH"
		}
	}
	return out
}

// capToolResultJudgeVerdict applies the tool-result disposition to a judge
// verdict: HIGH at most, with the action the connector's levels give HIGH.
// Secure Client keeps the judge verdict as it is (issue #1092).
func capToolResultJudgeVerdict(cfg *config.Config, connector string, v *ScanVerdict) *ScanVerdict {
	if v == nil || !strings.EqualFold(v.Severity, "CRITICAL") || (cfg != nil && cfg.SecureClientIntegration()) {
		return v
	}
	out := *v
	out.Severity = "HIGH"
	out.Action = guardrailContentAction(cfg, connector, "HIGH", false)
	return &out
}

// toolResultView is the text the injection checks read: JSON and C-style
// string escapes decoded and confusable letters folded. A tool output that is
// a JSON or YAML document carries its text as quoted strings ("a\nIgnore
// ..."); the model reads the escape as the character, the rules read a letter
// glued to the next word, and every anchored pattern misses it.
func toolResultView(content string) string {
	return trustPatternText(decodeStringEscapes(content))
}

// decodeStringEscapes decodes \n \r \t \" \' \\ \/ \uXXXX (surrogate pairs
// joined) and \xXX. Anything else is kept as written. Text without a
// backslash is returned unchanged, without a copy.
func decodeStringEscapes(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		switch n := s[i+1]; n {
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case '"', '\'', '\\', '/':
			b.WriteByte(n)
			i++
		case 'u':
			r, width := decodeUnicodeEscape(s[i:])
			if width == 0 {
				b.WriteByte(c)
				continue
			}
			b.WriteRune(r)
			i += width - 1
		case 'x':
			if i+3 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteRune(rune(v))
					i += 3
					continue
				}
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// decodeUnicodeEscape decodes the \uXXXX escape at the start of s (and a low
// surrogate right after a high one). width 0 means s does not start with one.
func decodeUnicodeEscape(s string) (rune, int) {
	hex4 := func(t string) (rune, bool) {
		if len(t) < 6 || t[0] != '\\' || t[1] != 'u' {
			return 0, false
		}
		v, err := strconv.ParseUint(t[2:6], 16, 16)
		return rune(v), err == nil
	}
	r, ok := hex4(s)
	if !ok {
		return 0, 0
	}
	if r >= 0xD800 && r < 0xDC00 {
		if lo, ok := hex4(s[6:]); ok && lo >= 0xDC00 && lo < 0xE000 {
			return (r-0xD800)<<10 + (lo - 0xDC00) + 0x10000, 12
		}
		return utf8.RuneError, 6
	}
	return r, 6
}
