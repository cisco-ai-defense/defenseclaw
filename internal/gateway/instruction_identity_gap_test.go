// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func instructionIdentityTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func instructionIdentityTestLink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	return link
}

// instructionIdentityContexts are the two ways a gateway learns a write
// target: the managed hook client's evidence (a gateway behind ProtectHome)
// and its own view of the file system (a per-user or Windows gateway).
func instructionIdentityContexts(t *testing.T, cwd, tool string, input map[string]interface{}) map[string]context.Context {
	t.Helper()
	contexts := map[string]context.Context{"gateway file system": t.Context()}
	if runtime.GOOS != "windows" {
		contexts["hook client evidence"] = instructionResolvedWriteContext(t, cwd, tool, input)
	}
	for name, ctx := range contexts {
		contexts[name] = withAuthenticatedHookConnector(ctx, "claudecode")
	}
	return contexts
}

// GAP-0869: a hard link is the instruction file under another name. Writing
// it through the link, natively or in a shell, is a write to the file, from
// the first call of a session and after a gateway restart.
func TestInstructionProtectionHardLinkAliasAnywhere(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	instruction := writeActiveAgentTestFile(t, project, "CLAUDE.md")
	for _, tc := range []struct{ name, alias string }{
		{"same directory", filepath.Join(project, "notes.txt")},
		{"other directory", filepath.Join(root, "scratch", "notes.txt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alias := instructionIdentityTestLink(t, instruction, tc.alias)
			calls := []struct {
				tool  string
				input map[string]interface{}
			}{
				{"Write", map[string]interface{}{"file_path": alias, "content": "changed"}},
				{"Edit", map[string]interface{}{"file_path": alias, "old_string": "test", "new_string": "changed"}},
			}
			if runtime.GOOS != "windows" {
				calls = append(calls, struct {
					tool  string
					input map[string]interface{}
				}{"Bash", map[string]interface{}{"command": "printf changed >> '" + alias + "'"}})
			}
			for _, call := range calls {
				for source, ctx := range instructionIdentityContexts(t, project, call.tool, call.input) {
					response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
						ctx, claudeCodeHookRequest{
							HookEventName: "PreToolUse", SessionID: "first-call", CWD: project,
							ToolName: call.tool, ToolInput: call.input,
						})
					if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
						t.Fatalf("%s %s through a hard link (%s): action=%q findings=%v", call.tool, tc.name, source, response.Action, response.Findings)
					}
				}
			}
		})
	}
}

// The gateway behind ProtectHome reads no file: the hook client's identity
// evidence alone decides, for a named file and for a new hard link whose
// source the client could not read.
func TestInstructionProtectionClientIdentityEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, identity, rule string
	}{
		{"named file", "/home/alice/project/CLAUDE.md", "COG-CLAUDE-MD"},
		{"uncheckable new hard link", hookpaths.InstructionIdentityUnknown, "COG-AGENTS-MD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := map[string]string{
				hookpaths.CWDKey:                 "/home/alice/project",
				"/home/alice/scratch/notes.txt":  "/home/alice/scratch/notes.txt",
				hookpaths.InstructionIdentityKey: tc.identity,
			}
			ctx := withAuthenticatedHookConnector(context.WithValue(t.Context(), resolvedWritesContextKey{}, targets), "claudecode")
			input := map[string]interface{}{"command": "printf changed >> /home/alice/scratch/notes.txt"}
			response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
				ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "protect-home", CWD: "/home/alice/project",
					ToolName: "Bash", ToolInput: input,
				})
			if runtime.GOOS == "windows" {
				// Windows paths: the client evidence is POSIX-only.
				return
			}
			if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, tc.rule) {
				t.Fatalf("identity %q: action=%q findings=%v", tc.identity, response.Action, response.Findings)
			}
		})
	}
}

// A file with several hard links is not protected for its link count: pnpm
// and uv stores hard-link package files into node_modules and .venv. A write,
// an edit or another hard link to one is judged as the release judges it.
func TestInstructionProtectionOrdinaryHardLinks(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	writeActiveAgentTestFile(t, project, "CLAUDE.md")
	stored := writeActiveAgentTestFile(t, filepath.Join(root, "store", "v10"), "00ab")
	installed := instructionIdentityTestLink(t, stored, filepath.Join(project, "node_modules", ".pnpm", "pkg", "index.js"))
	type call struct {
		tool  string
		input map[string]interface{}
	}
	calls := []call{
		{"Write", map[string]interface{}{"file_path": installed, "content": "changed"}},
		{"Edit", map[string]interface{}{"file_path": installed, "old_string": "test", "new_string": "changed"}},
	}
	if runtime.GOOS != "windows" {
		calls = append(calls,
			call{"Bash", map[string]interface{}{"command": "printf changed >> '" + installed + "'"}},
			call{"Bash", map[string]interface{}{"command": "ln '" + installed + "' '" + filepath.Join(root, "copy.js") + "'"}},
		)
	}
	for _, c := range calls {
		for source, ctx := range instructionIdentityContexts(t, project, c.tool, c.input) {
			// block_at HIGH: the instruction rules are HIGH or CRITICAL.
			response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
				ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "pnpm", CWD: project,
					ToolName: c.tool, ToolInput: c.input,
				})
			if response.Action == guardrailActionBlock {
				t.Fatalf("%s %v of an ordinary hard-linked file (%s) was blocked: %v", c.tool, c.input, source, response.Findings)
			}
			for rule := range instructionRuleFiles {
				if findingStringHasRuleID(response.Findings, rule) {
					t.Fatalf("%s %v of an ordinary hard-linked file (%s) got %s: %v", c.tool, c.input, source, rule, response.Findings)
				}
			}
		}
	}
}

// An instruction file the session loaded is protected under any name,
// wherever it lives (load provenance), at its own rule's severity. One in no
// agent folder that the session did not load is named only on Windows, which
// lists a file's names; POSIX writes it as the release does.
func TestInstructionProtectionLoadedFileHardLink(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	soul := writeActiveAgentTestFile(t, filepath.Join(root, "persona"), "SOUL.md")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := instructionIdentityTestLink(t, soul, filepath.Join(root, "scratch", "draft.txt"))
	input := map[string]interface{}{"file_path": alias, "content": "changed"}
	for source, ctx := range instructionIdentityContexts(t, project, "Write", input) {
		api := instructionProtectionTestAPI(t, "claudecode", "action", "CRITICAL")
		api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded", SessionID: "loaded", CWD: project, FilePath: soul,
		})
		// CRITICAL-only blocking still stops it: SOUL.md is CRITICAL.
		response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "loaded", CWD: project, ToolName: "Write", ToolInput: input,
		})
		if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-SOUL") ||
			response.Severity != "CRITICAL" {
			t.Fatalf("hard link to a loaded file (%s): action=%q severity=%q findings=%v", source, response.Action, response.Severity, response.Findings)
		}
		unloaded := instructionProtectionTestAPI(t, "claudecode", "action", "CRITICAL").evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "not-loaded", CWD: project, ToolName: "Write", ToolInput: input,
		})
		named := findingStringHasRuleID(unloaded.Findings, "COG-SOUL")
		if blocked := unloaded.Action == guardrailActionBlock; blocked != (runtime.GOOS == "windows") || named != blocked {
			t.Fatalf("hard link to an unloaded file in no agent folder (%s): action=%q findings=%v", source, unloaded.Action, unloaded.Findings)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	// Removing one name leaves the file intact.
	remove := map[string]interface{}{"command": "rm -f '" + alias + "'"}
	for source, ctx := range instructionIdentityContexts(t, project, "Bash", remove) {
		api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
		api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded", SessionID: "loaded", CWD: project, FilePath: soul,
		})
		response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "loaded", CWD: project, ToolName: "Bash", ToolInput: remove,
		})
		if response.Action == guardrailActionBlock {
			t.Fatalf("removing a hard-link name (%s) was blocked: %v", source, response.Findings)
		}
	}
}

// A new hard link to an instruction file is another name for it, so creating
// one is refused like a write. A symbolic link stays allowed: writes follow it.
func TestInstructionProtectionRefusesHardLinkCreation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms; TestInstructionProtectionWindowsHardLinks covers Windows")
	}
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	writeActiveAgentTestFile(t, project, "CLAUDE.md")
	writeActiveAgentTestFile(t, project, "AGENTS.md")
	writeActiveAgentTestFile(t, project, "plain.txt")
	for _, tc := range []struct {
		name, connector, tool, command, rule string
		blocked                              bool
	}{
		{"ln", "claudecode", "Bash", "ln CLAUDE.md notes.txt", "COG-CLAUDE-MD", true},
		{"cp link", "claudecode", "Bash", "cp --link CLAUDE.md /tmp/notes", "COG-CLAUDE-MD", true},
		{"python", "claudecode", "Bash", `python3 -c "import os; os.link('CLAUDE.md', 'n')"`, "COG-CLAUDE-MD", true},
		{"codex exec", "codex", "exec_command", "ln AGENTS.md notes.txt", "COG-AGENTS-MD", true},
		{"dynamic source", "claudecode", "Bash", `ln "$SRC" notes.txt`, "COG-AGENTS-MD", true},
		{"symbolic", "claudecode", "Bash", "ln -s CLAUDE.md notes.txt", "", false},
		{"ordinary", "claudecode", "Bash", "ln plain.txt plain2.txt", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, tc.connector, "action", "HIGH")
			var action string
			var findings []string
			if tc.connector == "codex" {
				input := map[string]interface{}{"cmd": tc.command}
				response := api.evaluateCodexHook(instructionResolvedWriteContext(t, project, tc.tool, input), codexHookRequest{
					HookEventName: "PreToolUse", SessionID: "link", CWD: project, ToolName: tc.tool, ToolInput: input,
				})
				action, findings = response.Action, response.Findings
			} else {
				input := map[string]interface{}{"command": tc.command}
				response := api.evaluateClaudeCodeHook(withAuthenticatedHookConnector(t.Context(), "claudecode"), claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "link", CWD: project, ToolName: tc.tool, ToolInput: input,
				})
				action, findings = response.Action, response.Findings
			}
			blocked := action == guardrailActionBlock
			if blocked != tc.blocked || tc.blocked && !findingStringHasRuleID(findings, tc.rule) {
				t.Fatalf("%q: action=%q findings=%v, want blocked=%t rule %s", tc.command, action, findings, tc.blocked, tc.rule)
			}
		})
	}
}

func TestInstructionProtectionObservesHardLinkWrite(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	instruction := writeActiveAgentTestFile(t, filepath.Join(root, "project"), "CLAUDE.md")
	alias := instructionIdentityTestLink(t, instruction, filepath.Join(root, "scratch", "notes.txt"))
	input := map[string]interface{}{"file_path": alias, "content": "changed"}
	response := instructionProtectionTestAPI(t, "claudecode", "observe", "HIGH").evaluateClaudeCodeHook(
		withAuthenticatedHookConnector(t.Context(), "claudecode"), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "observe", CWD: filepath.Join(root, "project"),
			ToolName: "Write", ToolInput: input,
		})
	if response.Action != "allow" || response.RawAction != "block" || !response.WouldBlock ||
		!findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
		t.Fatalf("observe mode hard-link write: %+v", response)
	}
}
