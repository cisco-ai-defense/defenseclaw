// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A startup location is only a candidate for a loaded instruction file. A
// write that creates one there has no existing file identity to protect.
func TestInstructionProtectionCreatingAbsentStartupFile(t *testing.T) {
	for _, tc := range []struct{ connector, name, rule string }{
		{"claudecode", "CLAUDE.md", "COG-CLAUDE-MD"},
		{"codex", "AGENTS.md", "COG-AGENTS-MD"},
		{"openclaw", "SOUL.md", "COG-SOUL"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			root := t.TempDir()
			project := filepath.Join(root, "project")
			if err := os.Mkdir(project, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(project, tc.name)
			api := instructionProtectionTestAPI(t, tc.connector, "action", "HIGH")
			for _, form := range []struct{ name, command string }{
				{"redirect", "printf x > '" + target + "'"},
				{"append", "printf x >> '" + target + "'"},
				{"tee", "printf x | tee '" + target + "'"},
			} {
				for _, withClientProof := range []bool{false, true} {
					name := form.name
					if withClientProof {
						name += "/client resolver"
					}
					t.Run(name, func(t *testing.T) {
						input := actionfacts.Input{Tool: "Bash", Command: form.command, CWD: project, ActiveHome: root}
						request := trustedActionRequest{Input: input, LegacyText: form.command,
							Connector: tc.connector, EnforcementCapable: true}
						if withClientProof {
							body := mustJSON(t, map[string]interface{}{
								"hook_event_name": "PreToolUse", "session_id": "creation", "cwd": project,
								"tool_name": "Bash", "tool_input": map[string]interface{}{"command": form.command},
							})
							targets, ok := hookpaths.Decode(hookpaths.Resolve(body))
							if !ok {
								t.Fatal("hook client did not resolve the write")
							}
							request.ResolvedWriteTargets = targets
						}
						verdict := api.inspectTrustedToolPolicyCtx(t.Context(),
							&ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: tc.connector}, request)
						if cogBlocked(verdict.Action, verdict.WouldBlock, verdict.Findings) {
							t.Fatalf("creating absent %s was blocked: %+v", tc.name, verdict)
						}
					})
				}
			}
			if err := os.WriteFile(target, []byte("loaded at startup\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			command := "printf x >> '" + target + "'"
			verdict := api.inspectTrustedToolPolicyCtx(t.Context(),
				&ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: tc.connector},
				trustedActionRequest{Input: actionfacts.Input{Tool: "Bash", Command: command, CWD: project, ActiveHome: root},
					LegacyText: command, Connector: tc.connector, EnforcementCapable: true})
			if verdict.Action != guardrailActionBlock || !findingStringHasRuleID(verdict.Findings, tc.rule) {
				t.Fatalf("existing startup %s lost protection: %+v", tc.name, verdict)
			}
		})
	}
}
