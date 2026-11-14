// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-0605: a prompt injection in a tool result was recorded
// (TRUST-* raw block) but answered allow in every pack, and the only thing the
// hook returned was hookSpecificOutput.additionalContext, which Claude Code
// gives the model and never shows the user. A tool result cannot be unread,
// so enforcement on PostToolUse is telling the agent and the user:
//   - strict and managed-strict (raw block): the connector's PostToolUse
//     block form, decision "block" with a reason telling the agent not to
//     follow the result's instructions;
//   - default, permissive and managed (raw alert): the agent-visible context
//     note, never a block;
//   - every pack, whenever there is an alert or a block: a systemMessage, the
//     one field Claude Code and Codex show the user.
//
// The rows are the TD repro shapes of S7/TD-TRIAGE.md (row ids g605-*), built
// from the existing trust-exploit fixture; benign twins carry the same tool
// shapes with ordinary output.

type gap0605Row struct {
	id       string
	tool     string
	input    map[string]interface{}
	response func(text string) interface{}
	benign   bool
}

func gap0605Rows() []gap0605Row {
	bashOut := func(text string) interface{} {
		return map[string]interface{}{"stdout": text, "stderr": "", "interrupted": false, "isImage": false}
	}
	readOut := func(path string) func(string) interface{} {
		return func(text string) interface{} {
			return map[string]interface{}{"type": "text", "file": map[string]interface{}{
				"filePath": path, "content": text, "numLines": strings.Count(text, "\n") + 1, "startLine": 1, "totalLines": strings.Count(text, "\n") + 1,
			}}
		}
	}
	fetchOut := func(text string) interface{} {
		return map[string]interface{}{"code": 200, "codeText": "OK", "result": text, "url": "https://example.invalid/notes"}
	}
	cat := map[string]interface{}{"command": "cat ../decoy/notes.txt"}
	curl := map[string]interface{}{"command": "curl -s http://127.0.0.1:8099/release.html"}
	read := map[string]interface{}{"file_path": "/srv/decoy/notes.txt"}
	fetch := map[string]interface{}{"url": "https://example.invalid/notes", "prompt": "summarize the page"}
	return []gap0605Row{
		{id: "g605-cat-inj", tool: "Bash", input: cat, response: bashOut},
		{id: "g605-curl-inj", tool: "Bash", input: curl, response: bashOut},
		{id: "g605-read-inj", tool: "Read", input: read, response: readOut("/srv/decoy/notes.txt")},
		{id: "g605-fetch-inj", tool: "WebFetch", input: fetch, response: fetchOut},
		{id: "g605-cat-benign", tool: "Bash", input: cat, response: bashOut, benign: true},
		{id: "g605-curl-benign", tool: "Bash", input: curl, response: bashOut, benign: true},
		{id: "g605-read-benign", tool: "Read", input: read, response: readOut("/srv/decoy/notes.txt"), benign: true},
		{id: "g605-fetch-benign", tool: "WebFetch", input: fetch, response: fetchOut, benign: true},
	}
}

// gap0605Text is the result text of a row: the existing trust-exploit fixture
// inside ordinary content, or the ordinary content alone.
func gap0605Text(row gap0605Row) string {
	ordinary := "Build notes for the project.\nRelease notes - all good."
	if row.benign {
		return ordinary
	}
	if strings.HasPrefix(row.id, "g605-curl") {
		// The comment holds the fixture on its own line, as the TD page did.
		return "<html><body>" + ordinary + "\n<!--\n" + trustExploitKeyword() + "\n--></body></html>"
	}
	return ordinary + "\n" + trustExploitKeyword()
}

func gap0605StrictTier(p gap0437Pack) bool { return p.pack == "strict" }

func TestGAP0605ClaudeCodeToolResultTellsAgentAndUser(t *testing.T) {
	for _, p := range gap0437Packs {
		for _, mode := range gap0437Modes {
			for _, row := range gap0605Rows() {
				t.Run(p.name+"/"+mode+"/"+row.id, func(t *testing.T) {
					a := gap0437Server(t, p, "claudecode", mode)
					resp := a.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
						HookEventName:  "PostToolUse",
						SessionID:      "gap0605",
						CWD:            t.TempDir(),
						PermissionMode: "bypassPermissions",
						ToolName:       row.tool,
						ToolInput:      row.input,
						ToolResponse:   row.response(gap0605Text(row)),
					})
					out := resp.ClaudeCodeOutput
					if row.benign {
						if resp.RawAction != "allow" || resp.Action != "allow" {
							t.Fatalf("benign twin: action=%s raw=%s findings=%v, want allow", resp.Action, resp.RawAction, resp.Findings)
						}
						if _, ok := out["systemMessage"]; ok {
							t.Fatalf("benign twin shows the user a message: %v", out)
						}
						return
					}
					wantRaw := "alert"
					if gap0605StrictTier(p) {
						wantRaw = "block"
					}
					if resp.RawAction != wantRaw {
						t.Fatalf("raw=%s severity=%s findings=%v, want %s", resp.RawAction, resp.Severity, resp.Findings, wantRaw)
					}
					notice, _ := out["systemMessage"].(string)
					if notice == "" || !strings.HasPrefix(notice, "DefenseClaw") {
						t.Fatalf("no user-visible systemMessage: %v", out)
					}
					if mode == "action" && gap0605StrictTier(p) {
						if resp.Action != "block" || resp.WouldBlock {
							t.Fatalf("strict action: action=%s would_block=%v, want an enforced block", resp.Action, resp.WouldBlock)
						}
						if out["decision"] != "block" {
							t.Fatalf("strict action: output %v, want decision block", out)
						}
						reason, _ := out["reason"].(string)
						if !strings.Contains(reason, connector.ToolResultInjectionGuidance) {
							t.Fatalf("block reason %q does not tell the agent not to follow the result", reason)
						}
						if !strings.HasPrefix(notice, "DefenseClaw blocked this tool result") {
							t.Fatalf("user notice %q does not say the result was blocked", notice)
						}
						return
					}
					if resp.Action == "block" {
						t.Fatalf("%s %s blocks a tool result: %v", p.name, mode, out)
					}
					if _, ok := out["decision"]; ok {
						t.Fatalf("non-block answer carries a decision: %v", out)
					}
					hso, _ := out["hookSpecificOutput"].(map[string]interface{})
					context, _ := hso["additionalContext"].(string)
					if hso["hookEventName"] != "PostToolUse" || !strings.Contains(context, connector.ToolResultInjectionGuidance) {
						t.Fatalf("agent context note missing the guidance: %v", out)
					}
					if strings.Contains(notice, connector.ToolResultInjectionGuidance) {
						t.Fatalf("user notice carries the agent guidance: %q", notice)
					}
				})
			}
		}
	}
}

func TestGAP0605CodexToolResultTellsAgentAndUser(t *testing.T) {
	for _, p := range gap0437Packs {
		for _, row := range gap0605Rows() {
			t.Run(p.name+"/"+row.id, func(t *testing.T) {
				a := gap0437Server(t, p, "codex", "action")
				resp := a.evaluateCodexHook(t.Context(), codexHookRequest{
					HookEventName: "PostToolUse",
					SessionID:     "gap0605",
					CWD:           t.TempDir(),
					ToolName:      row.tool,
					ToolInput:     row.input,
					ToolResponse:  row.response(gap0605Text(row)),
				})
				out := resp.CodexOutput
				if row.benign {
					if resp.RawAction != "allow" {
						t.Fatalf("benign twin: raw=%s findings=%v, want allow", resp.RawAction, resp.Findings)
					}
					if _, ok := out["systemMessage"]; ok {
						t.Fatalf("benign twin shows the user a message: %v", out)
					}
					return
				}
				notice, _ := out["systemMessage"].(string)
				if notice == "" {
					t.Fatalf("raw=%s: no user-visible systemMessage: %v", resp.RawAction, out)
				}
				if gap0605StrictTier(p) {
					reason, _ := out["reason"].(string)
					if resp.Action != "block" || out["decision"] != "block" || !strings.Contains(reason, connector.ToolResultInjectionGuidance) {
						t.Fatalf("strict: action=%s output=%v, want decision block with the guidance", resp.Action, out)
					}
					return
				}
				if resp.Action == "block" || out["decision"] != nil {
					t.Fatalf("%s blocks a tool result: %v", p.name, out)
				}
			})
		}
	}
}

// The profile mirrors (connector package) render the same PostToolUse answer
// as the gateway shapers: they shape the answer when the ordered-safety-rule
// merge raises a verdict.
func TestGAP0605ProfileMirrorsMatchPostToolUse(t *testing.T) {
	reason := connector.WithToolResultInjectionGuidance("matched: TRUST-X: a finding")
	claude := connector.NewClaudeCodeConnector().HookProfile(connector.SetupOpts{})
	codex := connector.NewCodexConnector().HookProfile(connector.SetupOpts{})
	for _, tc := range []struct{ action, raw, additional string }{
		{"block", "block", ""},
		{"alert", "alert", "DefenseClaw observed a HIGH Claude Code hook finding: " + reason},
		{"allow", "block", "DefenseClaw would block this in action mode: HIGH Claude Code hook finding: " + reason},
	} {
		want := claudeCodeOutput(claudeCodeHookRequest{HookEventName: "PostToolUse"}, tc.action, tc.raw, reason, tc.additional)
		got := claude.Respond(connector.HookRespondInput{
			Req: connector.HookProfileRequest{HookEventName: "PostToolUse"}, Action: tc.action, RawAction: tc.raw,
			Reason: reason, AdditionalContext: tc.additional, Caps: claude.Capabilities,
		}).Output
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("claudecode %s: profile %v, gateway %v", tc.action, got, want)
		}
		if _, ok := want["systemMessage"]; !ok {
			t.Fatalf("claudecode %s: no systemMessage in %v", tc.action, want)
		}
		wantCodex := codexOutput("PostToolUse", tc.action, tc.raw, reason, tc.additional)
		gotCodex := codex.Respond(connector.HookRespondInput{
			Req: connector.HookProfileRequest{HookEventName: "PostToolUse"}, Action: tc.action, RawAction: tc.raw,
			Reason: reason, AdditionalContext: tc.additional, Caps: codex.Capabilities,
		}).Output
		if !reflect.DeepEqual(gotCodex, wantCodex) {
			t.Fatalf("codex %s: profile %v, gateway %v", tc.action, gotCodex, wantCodex)
		}
		if _, ok := wantCodex["systemMessage"]; !ok {
			t.Fatalf("codex %s: no systemMessage in %v", tc.action, wantCodex)
		}
	}
	// A PostToolUse block is enforceable on Claude Code now; PostToolBatch
	// stays advisory.
	if !claudeCodeCanEnforce(claudeCodeHookRequest{HookEventName: "PostToolUse"}) ||
		claudeCodeCanEnforce(claudeCodeHookRequest{HookEventName: "PostToolBatch"}) {
		t.Fatal("claudeCodeCanEnforce: want PostToolUse enforceable, PostToolBatch advisory")
	}
	if !eventIn("PostToolUse", claude.Capabilities.BlockEvents) {
		t.Fatalf("claudecode BlockEvents %v lacks PostToolUse", claude.Capabilities.BlockEvents)
	}
}

func TestGAP0605UserNoticeWording(t *testing.T) {
	g := connector.ToolResultInjectionGuidance
	if got := connector.WithToolResultInjectionGuidance(connector.WithToolResultInjectionGuidance("rule X")); strings.Count(got, g) != 1 ||
		!strings.HasPrefix(got, "rule X. ") {
		t.Fatalf("guidance not appended once: %q", got)
	}
	if got := connector.ToolResultUserNotice("block", "rule X. "+g, ""); got != "DefenseClaw blocked this tool result: rule X. The agent was told not to follow instructions in it." {
		t.Fatalf("block notice = %q", got)
	}
	if got := connector.ToolResultUserNotice("alert", "", ""); got != "" {
		t.Fatalf("empty alert notice = %q", got)
	}
	if got := connector.ToolResultUserNotice("alert", "x", "DefenseClaw observed a HIGH finding: secret"); got != "DefenseClaw observed a HIGH finding: secret" {
		t.Fatalf("non-injection alert notice = %q", got)
	}
}

// A connector with no tool-result block form says so in its note in every
// posture, strict included: tool-result injection is alert only there
// (GAP-0605). Payload shapes follow flow_results_test.go r2Results; Cursor and
// Devin stand for the generic hook path (Copilot needs its registration
// header, covered by the same code).
func TestGAP0605AlertOnlyConnectorsSayTheLimit(t *testing.T) {
	out := gap0605Text(gap0605Row{id: "g605-cat-inj"})
	cases := []struct {
		connector, event, tool string
		payload                map[string]any
	}{
		{"cursor", "postToolUse", "Shell", map[string]any{"tool_output": out}},
		{"devin", "PostToolUse", "shell", map[string]any{"tool_response": map[string]any{"output": out}}},
	}
	for _, p := range []gap0437Pack{gap0437Packs[0], gap0437Packs[1]} {
		for _, tc := range cases {
			t.Run(p.name+"/"+tc.connector, func(t *testing.T) {
				a := gap0437Server(t, p, tc.connector, "action")
				body := map[string]any{
					"hook_event_name": tc.event, "session_id": "gap0605-" + tc.connector, "cwd": t.TempDir(),
					"tool_name": tc.tool, "tool_input": map[string]any{"command": "cat ../decoy/notes.txt"},
				}
				for k, v := range tc.payload {
					body[k] = v
				}
				resp := gap0437Serve(t, a.handleAgentHook(tc.connector), "/api/v1/hook/"+tc.connector, body)
				if resp["action"] == "block" {
					t.Fatalf("an alert-only connector answered block: %v", resp)
				}
				note, _ := resp["additional_context"].(string)
				want := "Tool-result injection is alert only on " + tc.connector
				if !strings.Contains(note, want) || !strings.Contains(note, connector.ToolResultInjectionGuidance) {
					t.Fatalf("note %q lacks the limit or the guidance (raw=%v)", note, resp["raw_action"])
				}
			})
		}
	}
}
