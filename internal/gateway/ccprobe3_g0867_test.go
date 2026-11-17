// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe3 old-API probe for rel-1-0-10:GAP-0867 (P2): the end-to-end cascade
// table of the fix (TestDecisionModelCascades, copied by s7-probe2 into
// ccprobe2_g0867_test.go), alone: the hook action of a tool call that System
// One blocks with confidence, per cascade (1 rules, 2 + decision model,
// 3 + judge) and connector, through cascadeAPIServer and inspectToolPolicy
// (old API at the pre-fix sha ebf3ed3699 = 8df1988e2b^). Pre-fix, cascade 3
// floored the block at HIGH (an alert in the default pack). The s7-probe2
// file also held a blockFloor unit row whose signature changed in the fix,
// so it did not build at the pre-fix sha. Scratch, test-only.

package gateway

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCCP3G0867_DecisionModelCascades(t *testing.T) {
	const args = `{"command":"make -C ./fixtures/reports"}`
	answers := map[string]struct {
		choice string
		pAllow float64
	}{
		"allow":   {"allow", 0.97},
		"block":   {"block", 0.05},
		"confirm": {"confirm", 0.30},
		"down":    {"", 0},
	}
	cases := []struct {
		cascade   int
		answer    string
		connector string
		want      string // hook action after the connector's mapping
		dmCalled  bool
		judgeRuns bool
	}{
		// 1. Rules only: the decision model is never called.
		{1, "allow", "claudecode", "allow", false, false},
		{1, "block", "claudecode", "allow", false, false},
		{1, "confirm", "codex", "allow", false, false},
		{1, "down", "codex", "allow", false, false},
		// 2. Rules then the decision model, no judge.
		{2, "allow", "claudecode", "allow", true, false},
		{2, "allow", "codex", "allow", true, false},
		{2, "block", "claudecode", "block", true, false},
		{2, "block", "codex", "block", true, false},
		{2, "confirm", "claudecode", "confirm", true, false}, // the native ask
		{2, "confirm", "codex", "alert", true, false},        // no ask: HIGH alert
		{2, "down", "claudecode", "allow", true, false},      // rule verdict stands
		{2, "down", "codex", "allow", true, false},
		// 3. Rules, decision model, judge.
		{3, "allow", "claudecode", "allow", true, false},
		{3, "allow", "codex", "allow", true, false},
		{3, "block", "claudecode", "block", true, true}, // System One's own block stands (GAP-0867)
		{3, "block", "codex", "block", true, true},
		{3, "confirm", "claudecode", "allow", true, true}, // the judge decides
		{3, "confirm", "codex", "allow", true, true},
		{3, "down", "claudecode", "allow", true, true},
		{3, "down", "codex", "allow", true, true},
	}
	for _, tc := range cases {
		name := strings.Join([]string{string(rune('0' + tc.cascade)), tc.answer, tc.connector}, "/")
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			url := "http://127.0.0.1:1/v1/systemone" // nothing listens: connection refused
			if ans := answers[tc.answer]; ans.choice != "" {
				url = countingDecisionModel(t, ans.choice, ans.pAllow, &calls).URL
			}
			judge := cleanToolJudgeProvider()
			a := cascadeAPIServer(t, tc.cascade, tc.connector, url, "", judge)
			verdict := a.inspectToolPolicy(&ToolInspectRequest{
				Tool: "Bash", Args: json.RawMessage(args), Direction: "tool_call", Connector: tc.connector,
			})
			if got := hookActionFor(t, tc.connector, verdict); got != tc.want {
				t.Fatalf("hook action = %q (verdict %+v), want %q", got, verdict, tc.want)
			}
			if tc.answer != "down" && (calls.Load() > 0) != tc.dmCalled {
				t.Fatalf("decision model called %d times, want called=%v", calls.Load(), tc.dmCalled)
			}
			if ran := len(judge.captured) > 0; ran != tc.judgeRuns {
				t.Fatalf("judge ran=%v, want %v", ran, tc.judgeRuns)
			}
			if tc.answer == "down" && strings.Contains(strings.Join(verdict.Findings, ","), decisionModelFindingID) {
				t.Fatalf("a decision model that is down left a finding: %+v", verdict)
			}
		})
	}
}
