// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// TestConnectorNativeShapesNeverWeakerThanClaudeCode: antigravity file tools
// (GAP-0779), Amp edit_file (GAP-0778), Copilot view and Cursor beforeReadFile
// (GAP-0781), Codex apply_patch (GAP-0780), antigravity run_command, and the
// shell and file tools of OpenCode, Devin, Hermes, Kiro and OpenClaw
// (shapeParityNativeMore) are judged at least as Claude Code's Bash, Write, Edit
// and Read of the same action, in 5 tiers.
func TestConnectorNativeShapesNeverWeakerThanClaudeCode(t *testing.T) {
	cases := shapeParityCases(t)
	if len(cases) < 100 {
		t.Fatalf("only %d fixture cases", len(cases))
	}
	if testing.Short() {
		cases = cases[:len(cases)/4]
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cwd := t.TempDir()
		handlers := shapeParityHandlers(t, p)
		checked := map[string]int{}
		for _, c := range cases {
			base := shapeParityHook(t, handlers["claudecode"], shapeParityCall{name: "claudecode", conn: "claudecode",
				event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, c.tool, c.args)}, p.managed)
			for _, call := range append(shapeParityNative(c.tool, c.args, cwd), shapeParityNativeMore(c.tool, c.args, cwd)...) {
				want, wantTool := base, c.tool
				if c.tool == "Bash" && runtime.GOOS == "windows" {
					// On a Windows gateway agy runs run_command in
					// PowerShell, and the shell tools that do not name
					// their shell get the Windows reading: their baseline
					// is the Claude Code PowerShell tool, not the Bash
					// tool (Git Bash there).
					wantTool = "PowerShell"
					want = shapeParityHook(t, handlers["claudecode"], shapeParityCall{name: "claudecode", conn: "claudecode",
						event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, wantTool, c.args)}, p.managed)
				}
				got := shapeParityHook(t, handlers[call.conn], call, p.managed)
				checked[call.conn]++
				if shapeParityRank[got] < shapeParityRank[want] {
					t.Errorf("%s %s: %s answered %s, Claude Code %s %s", p.name, c.id, call.name, got, wantTool, want)
				}
			}
		}
		shapeParityCheckedEveryConnector(t, checked)
	})
}
