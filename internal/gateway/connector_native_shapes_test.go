// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"runtime"
	"slices"
	"testing"
)

// TestConnectorNativeShapesNeverWeakerThanClaudeCode{Default,Strict,Permissive,Managed,ManagedStrict}:
// antigravity file tools (GAP-0779), Amp edit_file (GAP-0778), Copilot view and
// Cursor beforeReadFile (GAP-0781), Codex apply_patch (GAP-0780) and antigravity
// run_command are judged at least as Claude Code's Bash, Write, Edit and Read of the same
// action, in 5 tiers.
//
// One top-level test per tier: under -race the five tiers took 472 s in one
// test on a hosted runner (run 43831888457), more than a CI gateway shard
// plans with its 1.5x headroom under the 720 s cap (rel-1-0-10:GAP-0941); each
// tier is a fifth of it, and the shards can take them apart. The checks are the
// same in every tier, and TestConnectorNativeShapesCoverEveryTier keeps one
// test per tier of gap0437Packs.
func TestConnectorNativeShapesNeverWeakerThanClaudeCodeDefault(t *testing.T) {
	connectorNativeShapesNeverWeaker(t, "default")
}

func TestConnectorNativeShapesNeverWeakerThanClaudeCodeStrict(t *testing.T) {
	connectorNativeShapesNeverWeaker(t, "strict")
}

func TestConnectorNativeShapesNeverWeakerThanClaudeCodePermissive(t *testing.T) {
	connectorNativeShapesNeverWeaker(t, "permissive")
}

func TestConnectorNativeShapesNeverWeakerThanClaudeCodeManaged(t *testing.T) {
	connectorNativeShapesNeverWeaker(t, "managed")
}

func TestConnectorNativeShapesNeverWeakerThanClaudeCodeManagedStrict(t *testing.T) {
	connectorNativeShapesNeverWeaker(t, "managed-strict")
}

// connectorNativeShapeTiers are the tiers the tests above run, one each.
var connectorNativeShapeTiers = []string{"default", "strict", "permissive", "managed", "managed-strict"}

func TestConnectorNativeShapesCoverEveryTier(t *testing.T) {
	var packs []string
	for _, p := range gap0437Packs {
		packs = append(packs, p.name)
	}
	if !slices.Equal(packs, connectorNativeShapeTiers) {
		t.Fatalf("tiers %v, the native shape tests run %v: add or remove a test", packs, connectorNativeShapeTiers)
	}
}

func connectorNativeShapesNeverWeaker(t *testing.T, tier string) {
	i := slices.IndexFunc(gap0437Packs, func(p gap0437Pack) bool { return p.name == tier })
	if i < 0 {
		t.Fatalf("no tier %s in gap0437Packs", tier)
	}
	p := gap0437Packs[i]
	cases := shapeParityCases(t)
	if len(cases) < 100 {
		t.Fatalf("only %d fixture cases", len(cases))
	}
	if testing.Short() {
		cases = cases[:len(cases)/4]
	}
	cwd := t.TempDir()
	handlers := map[string]http.HandlerFunc{}
	for _, conn := range []string{"claudecode", "antigravity", "codex", "amp", "copilot", "cursor"} {
		srv := gap0437Server(t, p, conn, "action")
		installToolCallCorpusProfileConnector(t, conn, p.pack)
		handlers[conn] = srv.handleAgentHook(conn)
	}
	checked := 0
	for _, c := range cases {
		base := shapeParityHook(t, handlers["claudecode"], shapeParityCall{name: "claudecode", conn: "claudecode",
			event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, c.tool, c.args)}, p.managed)
		for _, call := range shapeParityNative(c.tool, c.args, cwd) {
			want, wantTool := base, c.tool
			if c.tool == "Bash" && runtime.GOOS == "windows" {
				// On a Windows gateway agy runs run_command in
				// PowerShell: its baseline is the Claude Code PowerShell
				// tool, not the Bash tool (Git Bash there).
				wantTool = "PowerShell"
				want = shapeParityHook(t, handlers["claudecode"], shapeParityCall{name: "claudecode", conn: "claudecode",
					event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, wantTool, c.args)}, p.managed)
			}
			got := shapeParityHook(t, handlers[call.conn], call, p.managed)
			checked++
			if shapeParityRank[got] < shapeParityRank[want] {
				t.Errorf("%s %s: %s answered %s, Claude Code %s %s", p.name, c.id, call.name, got, wantTool, want)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no native shape was checked")
	}
}
