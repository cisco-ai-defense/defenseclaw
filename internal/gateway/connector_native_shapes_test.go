// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"testing"
)

// TestConnectorNativeShapesNeverWeakerThanClaudeCode: antigravity file tools
// (GAP-0779), Amp edit_file (GAP-0778), Copilot view and Cursor beforeReadFile
// (GAP-0781), Codex apply_patch (GAP-0780) and antigravity run_command are
// judged at least as Claude Code's Bash, Write, Edit and Read of the same
// action, in 5 tiers.
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
				got := shapeParityHook(t, handlers[call.conn], call, p.managed)
				checked++
				if shapeParityRank[got] < shapeParityRank[base] {
					t.Errorf("%s %s: %s answered %s, Claude Code %s %s", p.name, c.id, call.name, got, c.tool, base)
				}
			}
		}
		if checked == 0 {
			t.Fatal("no native shape was checked")
		}
	})
}
