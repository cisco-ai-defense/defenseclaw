// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0867: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha ebf3ed3699 lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// D6: decide is retired (s7/sysone 1eb8bf9277); a cascade-3 confident block
// with a silent judge ends at System One's own block, as in cascade 2, in
// every pack (raise-only across layers, rel-1-0-10:GAP-0867).
func TestCCP2G0867_CascadeThreeConfidentBlockSilentJudge(t *testing.T) {
	floor := (&decisionModel{blockAt: 0.75, blockRiskScore: 1.5}).blockFloor(t.Context(), decisionResult{route: decisionBlock, risk: 0.95, riskScore: 1.9})
	floor.systemOneBlocked = true
	for posture, want := range map[string]string{"default": "block", "permissive": "block", "strict": "block"} {
		cfg := cascadeConfig(t, posture, nil)
		got := hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", strongerDecisionVerdict(nil, floor))
		if got.Action != want {
			t.Fatalf("%s pack: %s, want %s", posture, got.Action, want)
		}
		if !strongerDecisionVerdict(&ScanVerdict{Action: "allow", Severity: "NONE"}, floor).systemOneBlocked {
			t.Fatal("System One's block mark lost in the merge")
		}
	}
}

func TestCCP2G0867_DecisionModelCascades(t *testing.T) {
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

// TestDecisionFloorSurvivesALateJudge (GAP-0392): in cascade 3 a System One
// confident block reaches the judge; when the judge misses the hook answer
// window the hook answers with the decision-model floor, not with nothing.
func TestCCP2G0867_DecisionFloorSurvivesALateJudge(t *testing.T) {
	a, p := newFloorTestServer(t, 5*time.Second)
	// The hook reached the gateway 2.6 s ago: 0.8 s of the 3.4 s window left,
	// enough for the decision model, not for the 5 s judge.
	ctx := boundedHookContext(time.Now().Add(-2600 * time.Millisecond))
	t0 := time.Now()
	v := a.runHookJudge(ctx, "tool_call", "tool_call", "codex", `{"command":"go test ./internal/... -run TestSomething -count=1 -v"}`, "Bash", nil)
	if elapsed := time.Since(t0); elapsed > 2*time.Second {
		t.Fatalf("the hook held the answer %s past its window", elapsed)
	}
	// The floor is System One's own block (rel-1-0-10:GAP-0867).
	if v == nil || v.Severity != "CRITICAL" || v.Action != guardrailActionBlock || !hasFinding(v.Findings, decisionModelFindingID) {
		t.Fatalf("late judge: verdict = %+v, want the CRITICAL decision-model block", v)
	}
	select {
	case <-p.finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the late judge never finished")
	}
}
