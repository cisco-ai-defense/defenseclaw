// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// gap1151At is the string at path (object keys, or "0" for an array's first
// element) in the answer obj, "" when there is none.
func gap1151At(obj map[string]json.RawMessage, path ...string) string {
	var cur any
	b, _ := json.Marshal(obj)
	_ = json.Unmarshal(b, &cur)
	for _, k := range path {
		switch v := cur.(type) {
		case map[string]any:
			cur = v[k]
		case []any:
			if k != "0" || len(v) == 0 {
				return ""
			}
			cur = v[0]
		default:
			return ""
		}
	}
	s, _ := cur.(string)
	return s
}

func gap1151HasNote(s string) bool {
	return strings.Contains(s, "DefenseClaw: ") && strings.Contains(s, "egress slot") &&
		strings.Contains(s, "reaches only DefenseClaw") && strings.Contains(s, "not a network or DNS fault")
}

// GAP-1151: the GAP-0505 callout line (an actor kept to the DefenseClaw rule
// because another callout holds Substrate's egress slot) reached only Claude
// Code and Codex actors. Every kit connector whose answer already has a
// context field now carries it there, as an alert's context goes: Cursor,
// Copilot, Devin, Antigravity and Hermes in hook_output, Amp in the
// additional_context its plugin reads on a prompt. OpenCode's plugin reads
// only a decision and the actor's Kiro 2.x hooks show the agent nothing, so
// their answers stay as they are (a documented limit). Claude Code and Codex
// are unchanged.
func TestGAP1151CalloutNoteReachesEveryKitConnector(t *testing.T) {
	other := controller.CalloutStatus{Known: true, Holder: "default/other-callout:9443", FailMode: controller.CalloutFailClosed}
	const finding = "DefenseClaw observed a HIGH finding"
	type tc struct {
		name, connector, event, answer string
		// path is where the note goes; nil: the answer is unchanged.
		path []string
		// keep is text of the answer that must stay in the note's field.
		keep string
	}
	cases := []tc{
		{"claudecode prompt", "claudecode", "UserPromptSubmit", `{"action":"allow"}`,
			[]string{"claude_code_output", "hookSpecificOutput", "additionalContext"}, ""},
		{"codex prompt", "codex", "UserPromptSubmit", `{"action":"allow"}`,
			[]string{"codex_output", "hookSpecificOutput", "additionalContext"}, ""},
		{"cursor session start", "cursor", "sessionStart", `{"action":"allow"}`,
			[]string{"hook_output", "additional_context"}, ""},
		{"cursor tool result alert keeps its context", "cursor", "postToolUse",
			`{"action":"alert","additional_context":"` + finding + `","hook_output":{"additional_context":"` + finding + `"}}`,
			[]string{"hook_output", "additional_context"}, finding},
		{"copilot session start", "copilot", "sessionStart", `{"action":"allow"}`,
			[]string{"hook_output", "additionalContext"}, ""},
		{"copilot tool result", "copilot", "postToolUse", `{"action":"allow"}`,
			[]string{"hook_output", "additionalContext"}, ""},
		{"devin prompt", "devin", "UserPromptSubmit", `{"action":"allow"}`,
			[]string{"hook_output", "hookSpecificOutput", "additionalContext"}, ""},
		{"antigravity pre invocation", "antigravity", "PreInvocation", `{"action":"allow"}`,
			[]string{"hook_output", "injectSteps", "0", "ephemeralMessage"}, ""},
		{"hermes pre llm call", "hermes", "pre_llm_call", `{"action":"allow"}`,
			[]string{"hook_output", "context"}, ""},
		{"amp prompt", "amp", "agent.start", `{"action":"allow"}`,
			[]string{"additional_context"}, ""},
		{"amp prompt alert keeps its context", "amp", "agent.start", `{"action":"alert","additional_context":"` + finding + `"}`,
			[]string{"additional_context"}, finding},
		// Documented limits: no context field the agent reads.
		{"opencode tool result", "opencode", "tool.execute.after", `{"action":"allow"}`, nil, ""},
		{"kiro tool result", "kiro", "postToolUse", `{"action":"allow"}`, nil, ""},
		// Events whose answer has no context field.
		{"cursor prompt", "cursor", "beforeSubmitPrompt", `{"action":"allow","hook_output":{"continue":true}}`, nil, ""},
		{"copilot prompt", "copilot", "userPromptSubmitted", `{"action":"allow"}`, nil, ""},
		{"amp tool call", "amp", "tool.call", `{"action":"allow"}`, nil, ""},
		// A refusal keeps its answer, and so does a hook_output that is not
		// the connector's context-only answer.
		{"devin refusal", "devin", "UserPromptSubmit", `{"action":"block","reason":"no","hook_output":{"decision":"block","reason":"no"}}`, nil, ""},
		{"cursor other output", "cursor", "postToolUse", `{"action":"allow","hook_output":{"updated_mcp_tool_output":"x"}}`, nil, ""},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if c.path != nil {
			seen[c.connector] = true
		}
	}
	for _, name := range kit.Connectors() {
		limit := name == "opencode" || name == "kiro"
		if seen[name] == limit {
			t.Errorf("kit connector %s: carries the note in this table %v, want %v", name, seen[name], !limit)
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newSubstrateFixture(t)
			st := f.api.substrateState()
			st.cfg.EgressCallout = func(context.Context) (controller.CalloutStatus, bool) { return other, true }
			st.readCalloutView()
			reg := registry.Registration{Atespace: "eng-web", Name: "g1151-1", UID: subUID1, Connector: c.connector, Profile: "eng"}
			obj := gap0505Post(t, st, reg, c.event, c.answer)
			if c.path == nil {
				var want map[string]json.RawMessage
				_ = json.Unmarshal([]byte(c.answer), &want)
				got, _ := json.Marshal(obj)
				exp, _ := json.Marshal(want)
				if string(got) != string(exp) {
					t.Fatalf("the answer changed:\n got %s\nwant %s", got, exp)
				}
				return
			}
			s := gap1151At(obj, c.path...)
			if !gap1151HasNote(s) {
				got, _ := json.Marshal(obj)
				t.Fatalf("%s carries no callout note: %q (answer %s)", strings.Join(c.path, "."), s, got)
			}
			if strings.Contains(s, other.Holder) {
				t.Errorf("the note names the other callout: %q", s)
			}
			if c.keep != "" && !strings.HasPrefix(s, c.keep+"\n") {
				t.Errorf("the answer's own context was lost: %q", s)
			}
			if strings.Count(s, "egress slot") != 1 {
				t.Errorf("the note is not there exactly once: %q", s)
			}
		})
	}
}
