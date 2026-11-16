// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
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
			forms := []struct{ name, command string }{
				{"redirect", "printf x > '" + target + "'"},
				{"append", "printf x >> '" + target + "'"},
				{"tee", "printf x | tee '" + target + "'"},
			}
			dialect := actionfacts.DialectPOSIX
			if runtime.GOOS == "windows" {
				forms = []struct{ name, command string }{
					{"write", "Set-Content -LiteralPath '" + target + "' -Value x"},
					{"append", "Add-Content -LiteralPath '" + target + "' -Value x"},
					{"tee", "'x' | Tee-Object -FilePath '" + target + "'"},
				}
				dialect = actionfacts.DialectPowerShell
			}
			for _, form := range forms {
				for _, withClientProof := range []bool{false, true} {
					name := form.name
					if withClientProof {
						name += "/client resolver"
					}
					t.Run(name, func(t *testing.T) {
						input := actionfacts.Input{Tool: "Bash", Command: form.command, CWD: project, ActiveHome: root, DialectHint: dialect}
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
			if runtime.GOOS == "windows" {
				command = "Add-Content -LiteralPath '" + target + "' -Value x"
			}
			verdict := api.inspectTrustedToolPolicyCtx(t.Context(),
				&ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: tc.connector},
				trustedActionRequest{Input: actionfacts.Input{Tool: "Bash", Command: command, CWD: project, ActiveHome: root, DialectHint: dialect},
					LegacyText: command, Connector: tc.connector, EnforcementCapable: true})
			if verdict.Action != guardrailActionBlock || !findingStringHasRuleID(verdict.Findings, tc.rule) {
				t.Fatalf("existing startup %s lost protection: %+v", tc.name, verdict)
			}
		})
	}
}

// Codex has no InstructionsLoaded event. Its native patch tools must treat
// an absent AGENTS.md at session start as a file creation, even when the
// hook client resolves the new path.
func TestInstructionProtectionCodexCreatesAbsentAgentsWithPatch(t *testing.T) {
	for _, tc := range []struct {
		name, tool string
		input      map[string]interface{}
	}{
		{"apply patch", "apply_patch", map[string]interface{}{
			"command": "*** Begin Patch\n*** Add File: AGENTS.md\n+new instructions\n*** End Patch",
		}},
		{"exec patch heredoc", "exec_command", map[string]interface{}{
			"cmd": "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: AGENTS.md\n+new instructions\n*** End Patch\nPATCH",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := t.TempDir()
			api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
			api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "SessionStart", SessionID: "new-file", CWD: project,
			})
			ctx := instructionResolvedWriteContext(t, project, tc.tool, tc.input)
			response := api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", SessionID: "new-file", CWD: project,
				ToolName: tc.tool, ToolInput: tc.input,
			})
			if cogBlocked(response.Action, response.WouldBlock, response.Findings) {
				t.Fatalf("creating absent AGENTS.md through %s was blocked: %+v", tc.tool, response)
			}
		})
	}
}
