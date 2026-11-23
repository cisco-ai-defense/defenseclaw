// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKiroReadsAScriptNamedOnTheCommandLine: `sh <script>` with the script in
// the working directory is judged on the script body under Kiro as under
// Claude Code (GAP-0777). The bodies are the fixture's shell commands.
func TestKiroReadsAScriptNamedOnTheCommandLine(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	var bodies []struct{ id, body string }
	for _, c := range loadACPParityCases(t) {
		if !strings.EqualFold(c.Tool, "bash") {
			continue
		}
		var args struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(c.Args, &args) == nil && args.Command != "" {
			bodies = append(bodies, struct{ id, body string }{c.ID, args.Command})
		}
	}
	if testing.Short() && len(bodies) > 40 {
		bodies = bodies[:40]
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		claude := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		kiro := gap0437Server(t, p, "kiro", "action")
		installToolCallCorpusProfileConnector(t, "kiro", p.pack)
		blocked := 0
		for i, b := range bodies {
			dir := filepath.Join(t.TempDir(), fmt.Sprint(i))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "prog.sh"), []byte("#!/bin/sh\n"+b.body+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"command": "sh prog.sh"}
			base := shapeParityHook(t, claude.handleAgentHook("claudecode"), shapeParityCall{name: "claudecode", conn: "claudecode",
				event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", dir, "Bash", input)}, p.managed)
			if base == "block" {
				blocked++
			}
			for _, call := range []shapeParityCall{
				{name: "kiro/execute_bash", conn: "kiro", event: "preToolUse", body: shapeParityEnvelope("preToolUse", dir, "execute_bash", input)},
				{name: "kiro/v3", conn: "kiro", event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", dir, "execute_bash", input),
					headers: map[string]string{"X-DefenseClaw-Hook-Dialect": "v3"}},
			} {
				if got := shapeParityHook(t, kiro.handleAgentHook("kiro"), call, p.managed); shapeParityRank[got] < shapeParityRank[base] {
					t.Errorf("%s %s: %s answered %s, Claude Code %s", p.name, b.id, call.name, got, base)
				}
			}
		}
		if blocked == 0 && p.name == "strict" {
			t.Fatal("no script body blocked on Claude Code: the test reads nothing")
		}
	})
}
