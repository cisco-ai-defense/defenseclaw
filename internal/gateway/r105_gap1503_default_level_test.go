// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-0995 (the GAP-1503 class for Claude Code): action mode with the
// default pack's own block level blocks a write to the loaded CLAUDE.md, in
// the session and after a gateway restart. Observe records it and allows.
func TestR105GAP0995LoadedClaudeMDBlocksAtTheDefaultLevel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	root := t.TempDir()
	file := writeActiveAgentTestFile(t, root, "CLAUDE.md")
	for _, tc := range []struct{ mode, want string }{{"action", guardrailActionBlock}, {"observe", guardrailActionAllow}} {
		before := instructionProtectionTestAPI(t, "claudecode", tc.mode, "")
		before.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded", SessionID: "live", FilePath: file,
		})
		input := map[string]interface{}{"command": "printf changed >> CLAUDE.md"}
		ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, root, "Bash", input), "claudecode")
		for name, api := range map[string]*APIServer{"same gateway": before, "after restart": instructionProtectionTestAPI(t, "claudecode", tc.mode, "")} {
			response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "live", CWD: root, ToolName: "Bash", ToolInput: input,
			})
			if response.Action != tc.want || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("%s, %s: action=%q findings=%v, want %s with COG-CLAUDE-MD", tc.mode, name, response.Action, response.Findings, tc.want)
			}
		}
	}
	// A project file that is not an instruction file stays allowed.
	api := instructionProtectionTestAPI(t, "claudecode", "action", "")
	response := api.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "live", CWD: root, ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": "printf changed >> notes.txt"},
	})
	if response.Action == guardrailActionBlock {
		t.Fatalf("ordinary project write blocked: %v", response.Findings)
	}
}

// GAP-1414: CLAUDE.md, the SOUL.md it includes (@SOUL.md) and a third name
// are one file. Claude Code reports both loads; a write through the third
// name is judged by both names' rules and blocks in action mode at the
// default pack's level.
func TestR105GAP1414ThirdAliasOfTwoLoadedNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hard links in a shell form")
	}
	for _, resolve := range []bool{false, true} {
		root := t.TempDir()
		if resolve {
			root = instructionIdentityTestRoot(t)
		}
		project := filepath.Join(root, "w2e-v04")
		claude := writeActiveAgentTestFile(t, project, "CLAUDE.md")
		soul := instructionIdentityTestLink(t, claude, filepath.Join(project, "SOUL.md"))
		third := instructionIdentityTestLink(t, claude, filepath.Join(project, "third-alias.md"))
		api := instructionProtectionTestAPI(t, "claudecode", "action", "")
		ctx := authenticatedClaudeCodeTestContext()
		api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded", SessionID: "v04", CWD: project, FilePath: claude, LoadReason: "session_start", MemoryType: "Project",
		})
		api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded", SessionID: "v04", CWD: project, FilePath: soul, LoadReason: "include", MemoryType: "Project",
		})
		for _, call := range []struct {
			tool  string
			input map[string]interface{}
		}{
			{"Write", map[string]interface{}{"file_path": third, "content": "changed\n"}},
			{"Bash", map[string]interface{}{"command": "printf changed >> third-alias.md"}},
		} {
			response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "v04", CWD: project, ToolName: call.tool, ToolInput: call.input,
			})
			if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") ||
				!findingStringHasRuleID(response.Findings, "COG-SOUL") {
				t.Fatalf("%s through the third alias (resolved root %t): action=%q findings=%v", call.tool, resolve, response.Action, response.Findings)
			}
		}
	}
}

// GAP-2046: CLAUDE.md files a Claude Code session created stay its own
// while it lives, also after Claude Code reports them loaded
// (nested_traversal, include): action mode at the default level allows the
// next edit. The same files there before the session started still block.
func TestR105GAP2046SessionCreatedLoadedClaudeMDStaysOwn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	for _, existed := range []bool{false, true} {
		t.Run(map[bool]string{false: "session-created", true: "pre-existing"}[existed], func(t *testing.T) {
			project := filepath.Join(instructionIdentityTestRoot(t), "project")
			if err := os.MkdirAll(filepath.Join(project, "pkg"), 0o700); err != nil {
				t.Fatal(err)
			}
			files := []string{filepath.Join(project, "pkg", "CLAUDE.md"), filepath.Join(project, "CLAUDE.md")}
			if existed {
				for _, file := range files {
					if err := os.WriteFile(file, []byte("there first\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			api := instructionProtectionTestAPI(t, "claudecode", "action", "")
			ctx := authenticatedClaudeCodeTestContext()
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "SessionStart", SessionID: "own", CWD: project, Source: "startup",
			})
			write := func(file string) claudeCodeHookResponse {
				return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "own", CWD: project, ToolName: "Write",
					ToolInput: map[string]interface{}{"file_path": file, "content": "edited\n"},
				})
			}
			if !existed {
				for _, step := range []string{"create", "edit"} {
					for _, file := range files {
						if got := write(file); got.Action == guardrailActionBlock {
							t.Fatalf("%s %s: blocked: %v", step, file, got.Findings)
						}
						if err := os.WriteFile(file, []byte(step+"\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			for i, reason := range []string{"nested_traversal", "include"} {
				api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					HookEventName: "InstructionsLoaded", SessionID: "own", CWD: project,
					FilePath: files[i], LoadReason: reason, MemoryType: "Project",
				})
			}
			for _, file := range files {
				got := write(file)
				if blocked := got.Action == guardrailActionBlock; blocked != existed {
					t.Fatalf("loaded %s (there first %t): action=%q findings=%v", file, existed, got.Action, got.Findings)
				}
				if existed && !findingStringHasRuleID(got.Findings, "COG-CLAUDE-MD") {
					t.Fatalf("loaded %s blocked without COG-CLAUDE-MD: %v", file, got.Findings)
				}
			}
			input := map[string]interface{}{"command": "printf x >> CLAUDE.md"}
			bash := api.evaluateClaudeCodeHook(withAuthenticatedHookConnector(instructionResolvedWriteContext(t, project, "Bash", input), "claudecode"),
				claudeCodeHookRequest{HookEventName: "PreToolUse", SessionID: "own", CWD: project, ToolName: "Bash", ToolInput: input})
			if blocked := bash.Action == guardrailActionBlock; blocked != existed {
				t.Fatalf("Bash append to the loaded CLAUDE.md (there first %t): action=%q findings=%v", existed, bash.Action, bash.Findings)
			}
		})
	}
}
