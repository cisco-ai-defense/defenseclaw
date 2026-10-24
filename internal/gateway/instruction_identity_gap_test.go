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

func instructionIdentityTestSymlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
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

type instructionIdentityCall struct {
	tool  string
	input map[string]interface{}
}

// instructionIdentityWrites are a native Write and Edit of path, and on
// POSIX a shell append.
func instructionIdentityWrites(path string) []instructionIdentityCall {
	calls := []instructionIdentityCall{
		{"Write", map[string]interface{}{"file_path": path, "content": "changed"}},
		{"Edit", map[string]interface{}{"file_path": path, "old_string": "test", "new_string": "changed"}},
	}
	if runtime.GOOS != "windows" {
		calls = append(calls, instructionIdentityCall{"Bash", map[string]interface{}{"command": "printf changed >> '" + path + "'"}})
	}
	return calls
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
			for _, call := range instructionIdentityWrites(alias) {
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

// GAP-0971: project/CLAUDE.md is a symlink to an ordinary-named file with one
// link. Writing that physical file writes CLAUDE.md, in action mode, from
// the gateway's own view and from the hook client's evidence; observe mode
// reports it. A loaded symlinked SOUL.md outside the project is protected
// the same way at its own CRITICAL severity. Ordinary neighbors stay
// writable.
func TestInstructionProtectionSymlinkedInstructionTarget(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	shared := writeActiveAgentTestFile(t, filepath.Join(root, "shared"), "instructions.txt")
	neighbor := writeActiveAgentTestFile(t, filepath.Join(root, "shared"), "other.txt")
	instructionIdentityTestSymlink(t, shared, filepath.Join(project, "CLAUDE.md"))
	for _, call := range instructionIdentityWrites(shared) {
		for source, ctx := range instructionIdentityContexts(t, project, call.tool, call.input) {
			request := claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "symlinked", CWD: project, ToolName: call.tool, ToolInput: call.input,
			}
			response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(ctx, request)
			if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("%s of a symlinked CLAUDE.md's target (%s): action=%q findings=%v", call.tool, source, response.Action, response.Findings)
			}
			observed := instructionProtectionTestAPI(t, "claudecode", "observe", "HIGH").evaluateClaudeCodeHook(ctx, request)
			if observed.Action != "allow" || !observed.WouldBlock || !findingStringHasRuleID(observed.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("observe %s of a symlinked CLAUDE.md's target (%s): %+v", call.tool, source, observed)
			}
		}
	}
	for _, call := range instructionIdentityWrites(neighbor) {
		for source, ctx := range instructionIdentityContexts(t, project, call.tool, call.input) {
			response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "symlinked", CWD: project, ToolName: call.tool, ToolInput: call.input,
			})
			if response.Action == guardrailActionBlock {
				t.Fatalf("%s of an ordinary neighbor (%s) was blocked: %v", call.tool, source, response.Findings)
			}
		}
	}

	persona := writeActiveAgentTestFile(t, filepath.Join(root, "persona-src"), "soul.txt")
	soul := instructionIdentityTestSymlink(t, persona, filepath.Join(root, "persona", "SOUL.md"))
	input := map[string]interface{}{"file_path": persona, "content": "changed"}
	for source, ctx := range instructionIdentityContexts(t, project, "Write", input) {
		api := instructionProtectionTestAPI(t, "claudecode", "action", "CRITICAL")
		api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded", SessionID: "loaded", CWD: project, FilePath: soul,
		})
		response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "loaded", CWD: project, ToolName: "Write", ToolInput: input,
		})
		if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-SOUL") || response.Severity != "CRITICAL" {
			t.Fatalf("target of a loaded symlinked SOUL.md (%s): action=%q severity=%q findings=%v", source, response.Action, response.Severity, response.Findings)
		}
	}
}

// The gateway behind ProtectHome reads no file: the hook client's identity
// evidence alone decides.
func TestInstructionProtectionClientIdentityEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the client evidence is POSIX-only")
	}
	targets := map[string]string{
		hookpaths.CWDKey:                 "/home/alice/project",
		"/home/alice/scratch/notes.txt":  "/home/alice/scratch/notes.txt",
		hookpaths.InstructionIdentityKey: "/home/alice/project/CLAUDE.md",
	}
	ctx := withAuthenticatedHookConnector(context.WithValue(t.Context(), resolvedWritesContextKey{}, targets), "claudecode")
	input := map[string]interface{}{"command": "printf changed >> /home/alice/scratch/notes.txt"}
	response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
		ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "protect-home", CWD: "/home/alice/project",
			ToolName: "Bash", ToolInput: input,
		})
	if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
		t.Fatalf("client identity: action=%q findings=%v", response.Action, response.Findings)
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
	single := writeActiveAgentTestFile(t, filepath.Join(project, "src"), "main.go")
	calls := []instructionIdentityCall{
		{"Write", map[string]interface{}{"file_path": installed, "content": "changed"}},
		{"Edit", map[string]interface{}{"file_path": installed, "old_string": "test", "new_string": "changed"}},
		{"Write", map[string]interface{}{"file_path": single, "content": "changed"}},
		{"Write", map[string]interface{}{"file_path": filepath.Join(project, "src", "new.go"), "content": "new"}},
	}
	if runtime.GOOS != "windows" {
		calls = append(calls,
			instructionIdentityCall{"Bash", map[string]interface{}{"command": "printf changed >> '" + installed + "'"}},
			instructionIdentityCall{"Bash", map[string]interface{}{"command": "ln '" + installed + "' '" + filepath.Join(root, "copy.js") + "'"}},
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
// load location that the session did not load is not one of its instruction
// files, on any OS.
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
		unloaded := instructionProtectionTestAPI(t, "claudecode", "action", "CRITICAL").evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "not-loaded", CWD: project, ToolName: "Write", ToolInput: input,
		})
		if unloaded.Action == guardrailActionBlock || findingStringHasRuleID(unloaded.Findings, "COG-SOUL") {
			t.Fatalf("hard link to an unloaded file in no load location (%s): action=%q findings=%v", source, unloaded.Action, unloaded.Findings)
		}
		// CRITICAL-only blocking still stops it: SOUL.md is CRITICAL.
		response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "loaded", CWD: project, ToolName: "Write", ToolInput: input,
		})
		if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-SOUL") ||
			response.Severity != "CRITICAL" {
			t.Fatalf("hard link to a loaded file (%s): action=%q severity=%q findings=%v", source, response.Action, response.Severity, response.Findings)
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

// Normal file work is never blocked: an unrelated directory holds an
// instruction-named file that is in no load location and that the session
// did not load, and a hard link of it beside it. Writing that link is
// ordinary in action mode, from the gateway's own view and from the hook
// client's evidence. Once the session loads the file, or the agent works in
// that directory, the same write is a write to the instruction file.
func TestInstructionProtectionUnloadedInstructionFileNeighbors(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, rule string }{
		{"SOUL.md", "COG-SOUL"},
		{"CLAUDE.md", "COG-CLAUDE-MD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unrelated := filepath.Join(root, "unrelated-"+tc.rule)
			instruction := writeActiveAgentTestFile(t, unrelated, tc.name)
			notes := instructionIdentityTestLink(t, instruction, filepath.Join(unrelated, "notes.txt"))
			for _, call := range instructionIdentityWrites(notes) {
				for source, ctx := range instructionIdentityContexts(t, project, call.tool, call.input) {
					response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
						ctx, claudeCodeHookRequest{
							HookEventName: "PreToolUse", SessionID: "unrelated", CWD: project,
							ToolName: call.tool, ToolInput: call.input,
						})
					if response.Action == guardrailActionBlock {
						t.Fatalf("%s beside an unloaded %s (%s) was blocked: %v", call.tool, tc.name, source, response.Findings)
					}
					for rule := range instructionRuleFiles {
						if findingStringHasRuleID(response.Findings, rule) {
							t.Fatalf("%s beside an unloaded %s (%s) got %s: %v", call.tool, tc.name, source, rule, response.Findings)
						}
					}
				}
			}
			call := instructionIdentityWrites(notes)[0]
			for source, ctx := range instructionIdentityContexts(t, project, call.tool, call.input) {
				api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
				api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					HookEventName: "InstructionsLoaded", SessionID: "loaded", CWD: project, FilePath: instruction,
				})
				response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "loaded", CWD: project, ToolName: call.tool, ToolInput: call.input,
				})
				if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, tc.rule) {
					t.Fatalf("write beside a loaded %s (%s): action=%q findings=%v", tc.name, source, response.Action, response.Findings)
				}
			}
			for source, ctx := range instructionIdentityContexts(t, unrelated, call.tool, call.input) {
				response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
					ctx, claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "beside", CWD: unrelated,
						ToolName: call.tool, ToolInput: call.input,
					})
				if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, tc.rule) {
					t.Fatalf("write with the agent beside %s (%s): action=%q findings=%v", tc.name, source, response.Action, response.Findings)
				}
			}
		})
	}
}

// Creating a link writes no file, and text about links is not a write: an
// allow-listed shell runs every command here as the release does, in the
// default (observe) mode and in action mode, from the gateway's own view and
// from the hook client's evidence.
func TestInstructionProtectionLinkCommandsWriteNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms; TestInstructionProtectionWindowsHardLinks covers Windows")
	}
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	writeActiveAgentTestFile(t, project, "CLAUDE.md")
	writeActiveAgentTestFile(t, project, "AGENTS.md")
	writeActiveAgentTestFile(t, project, "plain.txt")
	for _, tc := range []struct {
		connector, command string
	}{
		{"claudecode", "ln CLAUDE.md notes.txt"},
		{"claudecode", "ln -f -- CLAUDE.md /tmp/x"},
		{"claudecode", "cp --link CLAUDE.md notes2.txt"},
		{"claudecode", "cp -al CLAUDE.md notes3.txt"},
		{"claudecode", "link CLAUDE.md notes4.txt"},
		{"claudecode", `ln "$SRC" notes.txt`},
		{"claudecode", `python3 -c "import os; os.link('CLAUDE.md', 'n')"`},
		{"claudecode", `python3 -c "exec('os.link(a, b)')"`},
		{"claudecode", `python3 -c "print(f'{os.link(a, b)}')"`},
		{"claudecode", `node -e "require('fs').linkSync('AGENTS.md', 'x')"`},
		{"claudecode", `python3 -c "print('os.link(')"`},
		{"claudecode", `python3 -c "print('see CLAUDE.md before os.link(')"`},
		{"claudecode", `node -e "console.log('fs.linkSync(')"`},
		{"claudecode", "sudo ln CLAUDE.md notes.txt"},
		{"claudecode", "sudo ln -s CLAUDE.md notes.txt"},
		{"claudecode", "env ln --symbolic CLAUDE.md notes.txt"},
		{"claudecode", "sh -c 'ln -s a b; ln CLAUDE.md notes.txt'"},
		{"claudecode", `find . -name CLAUDE.md -exec ln {} b \;`},
		{"claudecode", "printf 'AGENTS.md\\n' | xargs -I{} ln {} /tmp/x"},
		{"claudecode", "sudo cp -s CLAUDE.md notes.txt"},
		{"claudecode", "ln plain.txt plain2.txt && printf x >> plain2.txt"},
		{"codex", "ln AGENTS.md notes.txt"},
	} {
		input := map[string]interface{}{"command": tc.command}
		tool := "Bash"
		if tc.connector == "codex" {
			tool, input = "exec_command", map[string]interface{}{"cmd": tc.command}
		}
		contexts := map[string]context.Context{
			"hook client evidence": instructionResolvedWriteContext(t, project, tool, input),
			"gateway file system":  t.Context(),
		}
		for source, ctx := range contexts {
			for _, mode := range []string{"observe", "action"} {
				api := instructionProtectionTestAPI(t, tc.connector, mode, "HIGH")
				allowTool(api.scannerCfg, tool, tc.connector, "ordinary shell work")
				var action string
				var findings []string
				if tc.connector == "codex" {
					response := api.evaluateCodexHook(withAuthenticatedHookConnector(ctx, "codex"), codexHookRequest{
						HookEventName: "PreToolUse", SessionID: "link", CWD: project, ToolName: tool, ToolInput: input,
					})
					action, findings = response.Action, response.Findings
				} else {
					response := api.evaluateClaudeCodeHook(withAuthenticatedHookConnector(ctx, "claudecode"), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "link", CWD: project, ToolName: tool, ToolInput: input,
					})
					action, findings = response.Action, response.Findings
				}
				if action == guardrailActionBlock {
					t.Errorf("%q (%s, %s) was blocked: %v", tc.command, source, mode, findings)
				}
				for rule := range instructionRuleFiles {
					if findingStringHasRuleID(findings, rule) {
						t.Errorf("%q (%s, %s) got %s: %v", tc.command, source, mode, rule, findings)
					}
				}
			}
		}
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
