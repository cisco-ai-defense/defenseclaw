// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestBoundFamilyFindingsKeepTheir1010Severity pins the finding sets of the
// two ACTION-COMPOUND-LIMIT families of the DET111 bar (bar-t17v12 piece b:
// a state write beside the bound, and beside the bound and
// ACTION-PARSE-FAILURE). A bound alone is MEDIUM now (owner ruling
// GAP-0851/0962), so the call severity there is the highest of the other
// findings; that is the 1.0.10 verdict only while every other finding keeps
// its own 1.0.10 severity. want is each finding's severity measured at
// a64bfdb931 (the findings each verdict severity was taken over, per tier
// in gap0437Packs order: default, strict, permissive, managed,
// managed-strict); every reading the call decides must hold each rule at or
// above it, in all five tiers, on the hook and the inspect route.
func TestBoundFamilyFindingsKeepTheir1010Severity(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	const state, parse = "tamper.detector_state_write", "ACTION-PARSE-FAILURE"
	type sev5 = [5]decide.Severity
	const (
		L = decide.SevLow
		H = decide.SevHigh
		C = decide.SevCritical
	)
	rows := []struct {
		name, tool, cmd string
		want            map[string]map[string]sev5 // route -> rule -> per tier
	}{
		{"GAP-1239 awk bash -c", "Bash", `bash -c "awk 'BEGIN{printf \"x\" >> \"/home/alice/.defenseclaw/config.yaml\"}'"`,
			map[string]map[string]sev5{"hook-cc": {state: {H, H, H, H, H}}, "inspect-oc": {state: {H, C, H, H, C}}}},
		{"GAP-1239 sudo awk", "Bash", `sudo awk 'BEGIN{print "x" > "/home/alice/.defenseclaw/config.yaml"}'`,
			map[string]map[string]sev5{"hook-cc": {state: {H, H, H, H, H}}, "inspect-oc": {state: {H, C, H, H, C}}}},
		{"GAP-1300 pwsh", "Bash", `pwsh -NoProfile -Command "New-Item -Path $HOME/.defenseclaw/config.yaml -Value x -Force"`,
			map[string]map[string]sev5{"hook-cc": {state: {H, C, H, H, C}}, "inspect-oc": {state: {H, C, H, H, C}}}},
		{"GAP-1255 seed2", "PowerShell", `New-Item -Path /home/alice/.defenseclaw/config.yaml -Value x -Force`,
			map[string]map[string]sev5{"hook-cc": {state: {H, C, H, H, C}}, "inspect-oc": {state: {H, H, H, H, H}}}},
		{"GAP-1255 var", "PowerShell", `& { New-Item -Path /home/alice/.defenseclaw/config.yaml -Value x -Force }`,
			map[string]map[string]sev5{"hook-cc": {state: {H, C, H, H, C}},
				"inspect-oc": {state: {L, L, L, L, L}, parse: {L, C, L, C, C}}}},
	}
	got := map[string]decide.Severity{}
	prev := decideRecordHook
	decideRecordHook = func(_, _ string, in decide.Input, _ decide.Output) {
		for _, f := range in.Findings {
			got[f.RuleID] = max(got[f.RuleID], f.Severity)
		}
	}
	t.Cleanup(func() { decideRecordHook = prev })
	for ti, p := range gap0437Packs {
		for _, route := range []string{"hook-cc", "inspect-oc"} {
			connector := "claudecode"
			if route == "inspect-oc" {
				connector = "openclaw"
			}
			a := gap0437Server(t, p, connector, "action")
			for i, r := range rows {
				clear(got)
				if route == "hook-cc" {
					sid := fmt.Sprintf("bfam-%s-%d", p.name, i)
					gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
						"hook_event_name": "PreToolUse", "session_id": sid, "cwd": "/home/alice/proj",
						"tool_name": r.tool, "tool_use_id": "tu-" + sid, "tool_input": map[string]any{"command": r.cmd}})
				} else {
					gap0437Inspect(t, a, "/home/alice/proj", r.cmd)
				}
				for rule, want := range r.want[route] {
					if got[rule] < want[ti] {
						t.Errorf("%s %s %s: %s severity %d, want at least its 1.0.10 %d (findings %v)",
							p.name, route, r.name, rule, got[rule], want[ti], got)
					}
				}
			}
		}
	}
}
