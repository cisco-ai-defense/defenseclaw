// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1150 (sibling of GAP-1143): the kit's skillScanEvents and
// preToolEvents listed event names by hand, and Hermes (pre_tool_call,
// post_tool_call, pre_llm_call, on_session_start), Cursor
// (beforeSubmitPrompt, afterShellExecution, afterFileEdit, beforeReadFile),
// Copilot (userPromptSubmitted) and Antigravity (PreInvocation,
// PostInvocation) were missing, so those actors never ran the skill pass at
// their prompt, session start or tool result, and a stuck skill folder did
// not refuse their tool calls. The tables now come from the shared connector
// event map.
func TestGAP1150EveryConnectorsEventsRunTheSkillPass(t *testing.T) {
	for _, tc := range []struct {
		connector     string
		scan, preTool []string
	}{
		{"hermes", []string{"pre_llm_call", "post_tool_call", "on_session_start"}, []string{"pre_tool_call"}},
		{"cursor", []string{"beforeSubmitPrompt", "afterShellExecution", "afterFileEdit", "afterMCPExecution"}, []string{"beforeReadFile", "beforeShellExecution"}},
		{"copilot", []string{"userPromptSubmitted", "postToolUse", "sessionStart"}, []string{"preToolUse"}},
		{"antigravity", []string{"PreInvocation", "PostToolUse", "PostInvocation"}, []string{"PreToolUse"}},
		{"opencode", []string{"tool.execute.after", "session.created", "session.idle"}, []string{"tool.execute.before"}},
		{"amp", []string{"tool.result", "session.start", "agent.start", "agent.end"}, []string{"tool.call"}},
	} {
		for _, ev := range tc.scan {
			if !skillScanEvent(tc.connector, ev) {
				t.Errorf("%s %s does not run the skill pass", tc.connector, ev)
			}
		}
		for _, ev := range tc.preTool {
			if !preToolEvents[ev] {
				t.Errorf("%s %s is not a pre-tool event (a stuck folder does not refuse it)", tc.connector, ev)
			}
		}
	}
}

// GAP-1150: every event a kit connector's hook contracts declare (the names
// its actor's hooks are registered for) at a session start, turn start or
// end, or tool result runs the pass, and every tool-start event is a
// pre-tool event, so a connector added to the map is covered.
func TestGAP1150KitTablesCoverEveryContractEvent(t *testing.T) {
	for _, name := range Connectors() {
		contracts := connector.KnownHookContracts(name)
		for _, c := range contracts {
			spec, ok := connector.CorrelationSpecForConnector(name, c.ContractID)
			if !ok {
				continue
			}
			for _, ev := range c.Events {
				l, ok := spec.LifecycleForEvent(ev)
				if !ok {
					continue
				}
				switch l {
				case connector.CorrelationLifecycleToolStart:
					if !preToolEvents[ev] {
						t.Errorf("%s (%s) %s: a tool start that is not a pre-tool event", name, c.ContractID, ev)
					}
				case connector.CorrelationLifecycleSessionStart, connector.CorrelationLifecycleTurnStart,
					connector.CorrelationLifecycleToolEnd, connector.CorrelationLifecycleTurnEnd:
					if name != "claudecode" && !skillScanEvent(name, ev) {
						t.Errorf("%s (%s) %s: does not run the skill pass", name, c.ContractID, ev)
					}
				}
			}
		}
	}
}

// GAP-1150: the Claude Code kit's behaviour stays as at rel: the same four
// scan events, and its PostToolUseFailure and PermissionDenied (tool-end
// names in the map) do not run the pass.
func TestGAP1150ClaudeKitScanEventsUnchanged(t *testing.T) {
	var got []string
	for _, ev := range []string{"UserPromptSubmit", "PostToolUse", "SessionStart", "Stop", "PostToolUseFailure", "PermissionDenied",
		"SubagentStop", "PreToolUse", "SessionEnd", "Notification", "PreCompact"} {
		if skillScanEvent("claudecode", ev) {
			got = append(got, ev)
		}
	}
	if want := []string{"UserPromptSubmit", "PostToolUse", "SessionStart", "Stop"}; !slices.Equal(got, want) {
		t.Fatalf("claudecode scan events %v, want %v", got, want)
	}
	if !preToolEvents["PreToolUse"] || preToolEvents["PostToolUse"] || preToolEvents["UserPromptSubmit"] {
		t.Fatal("claudecode pre-tool events changed")
	}
}
