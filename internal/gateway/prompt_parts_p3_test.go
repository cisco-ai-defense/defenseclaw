// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10:GAP-0528 (the text blocks of a tool result), GAP-0529 (the user
// messages of one turn) and GAP-0530 (a line feed inside a TRUST-AUTHORITY
// phrase). Literals are rows of the regex corpus, pinned by row id and rule id;
// a split point is searched, never written out.

func newPartJoinAPI(t *testing.T) *APIServer {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	return &APIServer{scannerCfg: cfg, store: store, logger: logger}
}

func partJoinToolResultRules(api *APIServer, content string) []string {
	verdict := api.inspectMessageContent(context.Background(), &ToolInspectRequest{
		Tool: "message", Content: content, Direction: "tool_result", Connector: "hermes", contentScope: ruleContentScopeUntrusted,
	})
	var rules []string
	if verdict != nil {
		for _, f := range verdict.DetailedFindings {
			rules = append(rules, f.RuleID)
		}
	}
	return rules
}

// toolResultShapes is one block list as the shapes of a tool result a hook
// sees: the content array alone, an MCP result object, an Anthropic
// tool_result block, and the same JSON pretty-printed in a string. Each is
// given as the content the hook builds for the rules (structuredHookContentString:
// the string leaves, then the JSON) except the last, which is a raw string.
func toolResultShapes(t *testing.T, blocks []map[string]any) map[string]string {
	t.Helper()
	pretty, err := json.MarshalIndent(map[string]any{"content": blocks, "isError": false}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"content array":   structuredHookContentString(blocks),
		"mcp result":      structuredHookContentString(map[string]any{"content": blocks, "isError": false}),
		"tool_result":     structuredHookContentString([]any{map[string]any{"type": "tool_result", "tool_use_id": "tu-1", "content": blocks}}),
		"pretty-printed":  string(pretty),
		"bedrock untyped": structuredHookContentString([]any{map[string]any{"text": blocks[0]["text"]}, map[string]any{"text": blocks[1]["text"]}}),
	}
}

func TestToolResultSplitLiteralFoundByRuleID(t *testing.T) {
	api := newPartJoinAPI(t)
	for _, tc := range partJoinCases {
		for _, n := range []int{2, 3} {
			parts := partJoinSplit(t, tc.row, tc.rule, n)
			blocks := partJoinBlocks("text", parts)
			for name, content := range toolResultShapes(t, blocks) {
				if name == "bedrock untyped" && n == 3 {
					continue
				}
				if got := partJoinToolResultRules(api, content); !slices.Contains(got, tc.rule) {
					t.Errorf("%s %s %d parts: rules %v, want %s", name, tc.row, n, got, tc.rule)
				}
			}
			// Control: the same parts as one string with a line feed between
			// them are not a literal.
			if got := partJoinToolResultRules(api, strings.Join(parts, "\n")); slices.Contains(got, tc.rule) {
				t.Errorf("%s %d parts: control (line-feed join) found %s", tc.row, n, tc.rule)
			}
		}
	}

	// The hook route: a Hermes post_tool_call whose result is a content array.
	profile := connector.NewHermesConnector().HookProfile(connector.SetupOpts{APIAddr: "127.0.0.1:18970"})
	for _, tc := range partJoinCases {
		parts := partJoinSplit(t, tc.row, tc.rule, 2)
		got := api.evaluateAgentHook(t.Context(), normalizeAgentHookRequestWithProfile("hermes", map[string]interface{}{
			"hook_event_name": "post_tool_call", "tool_name": "web_fetch", "session_id": "sess-partjoin-tr",
			"extra": map[string]interface{}{"result": partJoinBlocks("text", parts)},
		}, profile))
		if !slices.Contains(got.RuleIDs, tc.rule) {
			t.Errorf("hook %s: rules %v, want %s", tc.row, got.RuleIDs, tc.rule)
		}
	}
}

// What is not a content block array is not read as one text, and a seam that
// is not in the text adds no finding.
func TestToolResultPartsViewIsOnlyForTextBlocks(t *testing.T) {
	api := newPartJoinAPI(t)
	for _, tc := range partJoinCases {
		parts := partJoinSplit(t, tc.row, tc.rule, 2)
		// Records that happen to carry a text field are JSON, not one text.
		records := []map[string]any{{"id": 1, "text": parts[0]}, {"id": 2, "text": parts[1]}}
		if got := partJoinToolResultRules(api, structuredHookContentString(records)); slices.Contains(got, tc.rule) {
			t.Errorf("%s: a list of records is read as one text (%v)", tc.row, got)
		}
		// Blocks that are not text (an image with a caption field) are skipped.
		captions := []map[string]any{{"type": "image", "text": parts[0]}, {"type": "image", "text": parts[1]}}
		if got := partJoinToolResultRules(api, structuredHookContentString(captions)); slices.Contains(got, tc.rule) {
			t.Errorf("%s: image captions are read as one text (%v)", tc.row, got)
		}
	}
	for _, tc := range []struct{ content, view string }{
		{`plain text result`, ""},
		{`[{"type":"text","text":"alone"}]`, ""},
		{`[{"type":"text","text":"alp"},{"type":"text","text":"ha"}]`, "alpha"},
		{"alp\nha\n" + `[{"text":"alp"},{"text":"ha"}]`, "alpha"},
		{`{"content":[{"type":"text","text":"a"},{"type":"image","source":{}},{"type":"text","text":"b"}],"x":[{"type":"text","text":"c"},{"type":"output_text","text":"d"}]}`, "ab\ncd"},
		{`[{"text":"a","extra":1},{"text":"b","extra":2}]`, ""},
	} {
		if got := toolResultPartsJoinedText(tc.content); got != tc.view {
			t.Errorf("tool result %q: view %q, want %q", tc.content, got, tc.view)
		}
		if got := toolResultPartsJoinedText(tc.content); len(got) > len(tc.content) {
			t.Errorf("tool result %q: view is longer than the content", tc.content)
		}
	}

	// Benign rows cut in two blocks at every 7th point: no rule fires that the
	// row as one string does not.
	generation := snapshotRulePackGeneration("")
	for _, row := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
		if row.IsAttack || len(row.Content) < 8 {
			continue
		}
		whole := map[string]bool{}
		for _, f := range scanContentRuleCategoryWithGeneration(generation, row.Content, "", ruleContentScopeUntrusted, "") {
			whole[f.RuleID] = true
		}
		for i := 1; i < len(row.Content); i += 7 {
			if !utf8.RuneStart(row.Content[i]) {
				continue
			}
			blocks := partJoinBlocks("text", []string{row.Content[:i], row.Content[i:]})
			content := structuredHookContentString(blocks)
			base := map[string]bool{}
			for _, f := range scanContentRuleCategoryWithGeneration(generation, content, "", ruleContentScopeUntrusted, "") {
				base[f.RuleID] = true
			}
			for _, rule := range partJoinToolResultRules(api, content) {
				if !whole[rule] && !base[rule] {
					t.Errorf("benign row %s cut %d: %s fires only in the joined view", row.ID, i, rule)
				}
			}
		}
	}
}

func TestPromptSplitAcrossUserMessagesOfOneTurn(t *testing.T) {
	for _, strategy := range []string{"regex_only", "regex_judge", "judge_first"} {
		inspector := newPartJoinInspector(t, strategy)
		check := func(messages []ChatMessage) []string {
			raw := promptInspectText(messages)
			verdict := inspectPromptWithRawRecheck(context.Background(), inspector, promptInspectionText(raw), raw, messages, "model", "action")
			if verdict == nil {
				return nil
			}
			return verdict.Findings
		}
		for _, tc := range partJoinCases {
			for _, n := range []int{2, 3} {
				parts := partJoinSplit(t, tc.row, tc.rule, n)
				var turn []ChatMessage
				for _, part := range parts {
					turn = append(turn, ChatMessage{Role: "user", Content: part})
				}
				if !partJoinHasRule(check(turn), tc.rule) {
					t.Errorf("%s %s %d messages: %s not found", strategy, tc.row, n, tc.rule)
				}
				// A message of the turn that has parts of its own is read as its parts.
				blocks := partJoinChatMessages(t, string(mustJSON(t, []map[string]any{
					{"role": "user", "content": partJoinBlocks("text", []string{parts[0], parts[1][:1]})},
					{"role": "user", "content": parts[1][1:]},
				})))
				if n == 2 && !partJoinHasRule(check(blocks), tc.rule) {
					t.Errorf("%s %s: parts then message: %s not found", strategy, tc.row, tc.rule)
				}
				// Not one turn: an assistant message between them, or only the
				// earlier message of history.
				apart := append([]ChatMessage{turn[0], {Role: "assistant", Content: "ok"}}, turn[1:]...)
				if partJoinHasRule(check(apart), tc.rule) {
					t.Errorf("%s %s %d messages: found %s across an assistant message", strategy, tc.row, n, tc.rule)
				}
			}
		}
	}
}

// Consecutive user messages are not read as one text by accident: benign rows
// split over two messages add nothing the row as one string does not have.
func TestUserMessageSeamAddsNothingBenign(t *testing.T) {
	inspector := newPartJoinInspector(t, "regex_only")
	for _, row := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
		if row.IsAttack || (row.Direction != "" && row.Direction != "prompt") || len(row.Content) < 8 {
			continue
		}
		verdictOf := func(messages []ChatMessage) string {
			raw := promptInspectText(messages)
			v := inspectPromptWithRawRecheck(context.Background(), inspector, promptInspectionText(raw), raw, messages, "model", "action")
			if v == nil {
				return "NONE/allow"
			}
			return v.Severity + "/" + v.Action
		}
		whole := verdictOf([]ChatMessage{{Role: "user", Content: row.Content}})
		for i := 1; i < len(row.Content); i += 5 {
			if !utf8.RuneStart(row.Content[i]) || strings.TrimSpace(row.Content[:i]) == "" || strings.TrimSpace(row.Content[i:]) == "" {
				continue
			}
			split := verdictOf([]ChatMessage{{Role: "user", Content: row.Content[:i]}, {Role: "user", Content: row.Content[i:]}})
			if whole == "NONE/allow" && split != "NONE/allow" && split != verdictOf([]ChatMessage{{Role: "user", Content: row.Content[:i] + "\n" + row.Content[i:]}}) {
				t.Errorf("benign row %s cut %d: two messages give %s, one string %s", row.ID, i, split, whole)
			}
		}
	}
}

// GAP-0530: every rule of the trust pack treats any whitespace like a space,
// so a line feed in a phrase (a part seam in a provider that joins parts with
// a space, or an attacker's own) does not hide it. Checked on every enforceable
// attack row of the regex corpus: each single space replaced by a line feed
// keeps every rule the row has.
func TestTrustRulesMatchAcrossALineFeed(t *testing.T) {
	generation := snapshotRulePackGeneration("")
	rulesOf := func(text string) map[string]bool {
		out := map[string]bool{}
		for _, f := range scanContentRuleCategoryWithGeneration(generation, text, "", ruleContentScopeUntrusted, "") {
			if strings.HasPrefix(f.RuleID, "TRUST-") && f.contributesToEnforcement() {
				out[f.RuleID] = true
			}
		}
		return out
	}
	cuts, rows := 0, 0
	for _, row := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
		if !row.IsAttack || (row.Direction != "" && row.Direction != "prompt") {
			continue
		}
		whole := rulesOf(row.Content)
		if len(whole) == 0 {
			continue
		}
		rows++
		for i := 0; i < len(row.Content); i++ {
			if row.Content[i] != ' ' {
				continue
			}
			cuts++
			got := rulesOf(row.Content[:i] + "\n" + row.Content[i+1:])
			for rule := range whole {
				if !got[rule] {
					t.Errorf("row %s space %d: %s lost when the space is a line feed", row.ID, i, rule)
				}
			}
		}
	}
	if rows == 0 || cuts == 0 {
		t.Fatal("no row to check")
	}
	t.Logf("%d rows, %d single-space swaps", rows, cuts)
}

// The joined view of a tool result is for the trust rules: the end of one block
// and the start of the next are not one key or number for the secret and PII
// rules, and the unescaped text of a JSON item is not a new plain string (the
// owner trace cases that raised ENT-BULK-SSN-NOHYPHEN in the strict pack when
// the view read every rule).
func TestToolResultPartsViewIsTrustRulesOnly(t *testing.T) {
	api := newPartJoinAPI(t)
	parts := []string{"token AKIAQ3XK7PD", "2MZ5WJ8HR end"}
	generation := snapshotRulePackGeneration("")
	whole := scanContentRuleCategoryWithGeneration(generation, strings.Join(parts, ""), "message", ruleContentScopeUntrusted, "")
	if len(whole) == 0 || whole[0].RuleID != "SEC-AWS-KEY" {
		t.Fatalf("the joined text no longer holds an AWS key: %+v", whole)
	}
	if got := partJoinToolResultRules(api, structuredHookContentString(partJoinBlocks("text", parts))); slices.Contains(got, "SEC-AWS-KEY") {
		t.Errorf("a tool result's joined blocks are read by a secret rule: %v", got)
	}
	// The same parts as a prompt are still read joined by every rule.
	messages := partJoinChatMessages(t, string(mustJSON(t, []map[string]any{{"role": "user", "content": partJoinBlocks("text", parts)}})))
	if got := promptPartsJoinedText(promptInspectText(messages), messages, nil); got != strings.Join(parts, "") {
		t.Errorf("prompt view %q", got)
	}
	verdict := api.inspectMessageContent(context.Background(), &ToolInspectRequest{
		Tool: "message", Content: string(mustJSON(t, partJoinBlocks("text", parts))), Direction: "prompt", Connector: "hermes",
	})
	if verdict == nil || !slices.Contains(verdict.Findings, "SEC-AWS-KEY:"+whole[0].Title) {
		t.Errorf("hook prompt of two blocks: %+v", verdict)
	}
}
