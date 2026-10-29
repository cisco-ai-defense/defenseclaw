// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0768: the Windows path a Git Bash operand names, on any build host.
func TestR105GAP0768WindowsHostPathOfPOSIXOperand(t *testing.T) {
	cwd, home := `C:\Users\alice\proj`, `C:\Users\alice`
	for _, tc := range []struct{ value, want string }{
		{"CLAUDE.md", "C:/Users/alice/proj/CLAUDE.md"},
		{"./sub/../CLAUDE.md", "C:/Users/alice/proj/CLAUDE.md"},
		{"../AGENTS.md", "C:/Users/alice/AGENTS.md"},
		{`C:\Users\alice\proj\CLAUDE.md`, "C:/Users/alice/proj/CLAUDE.md"},
		{"C:/Users/alice/proj/CLAUDE.md", "C:/Users/alice/proj/CLAUDE.md"},
		{"/c/Users/alice/proj/CLAUDE.md", "C:/Users/alice/proj/CLAUDE.md"},
		{"~/.claude/CLAUDE.md", "C:/Users/alice/.claude/CLAUDE.md"},
		{"/tmp/CLAUDE.md", ""},
		{"/usr/bin/x", ""},
		{"~bob/CLAUDE.md", ""},
		{"$HOME/CLAUDE.md", ""},
		{"*.md", ""},
		{"", ""},
	} {
		got, ok := windowsHostPathOfPOSIXOperand(tc.value, cwd, home)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%q: got %q %v, want %q", tc.value, got, ok, tc.want)
		}
	}
	if got, ok := windowsHostPathOfPOSIXOperand("CLAUDE.md", "/repo", "/home/alice"); ok {
		t.Errorf("a POSIX working directory is not a Windows host path: %q", got)
	}
}

// GAP-0768 (P1, native Windows): Claude Code's Bash tool runs Git Bash. A
// write it makes to the CLAUDE.md the session loaded blocks in action
// (block_at HIGH) in every spelling; an ordinary write, a read and a mention
// stay allowed.
func TestR105GAP0768WindowsGitBashWriteToLoadedClaudeMD(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows host paths")
	}
	project := instructionIdentityTestRoot(t)
	file := writeActiveAgentTestFile(t, project, "CLAUDE.md")
	msys := "/" + strings.ToLower(file[:1]) + filepath.ToSlash(file[2:])
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{"echo MODIFIED > CLAUDE.md", true},
		{"printf x >> ./CLAUDE.md", true},
		{"echo MODIFIED > '" + file + "'", true},
		{"echo MODIFIED > " + filepath.ToSlash(file), true},
		{"echo MODIFIED > " + msys, true},
		{"echo ok > control.txt", false},
		{"cat CLAUDE.md", false},
		{"echo CLAUDE.md > notes.txt", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
			ctx := authenticatedClaudeCodeTestContext()
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "InstructionsLoaded", SessionID: "gitbash", CWD: project, FilePath: file})
			response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gitbash", CWD: project, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": tc.command},
			})
			if got := response.Action == guardrailActionBlock; got != tc.block ||
				tc.block && !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("action=%q findings=%v reason=%q, want block=%v", response.Action, response.Findings, response.Reason, tc.block)
			}
		})
	}
}

// GAP-2370 (P2 security, native Windows): Claude Code's Bash tool runs Git
// Bash, and `powershell -Command "Add-Content CLAUDE.md ..."` from it writes
// the CLAUDE.md the session loaded through the PowerShell body, which the
// outer shell call does not name. It blocks in action like the Git Bash
// spellings; an ordinary PowerShell write, a read and a mention stay allowed.
func TestR105GAP2370WindowsPowerShellCommandWriteToLoadedClaudeMD(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows host paths")
	}
	project := instructionIdentityTestRoot(t)
	file := writeActiveAgentTestFile(t, project, "CLAUDE.md")
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`powershell -Command "Add-Content CLAUDE.md '- reviewed'"`, true},
		{`powershell -Command "Add-Content ` + file + ` '- reviewed'"`, true},
		{`powershell.exe -Command "Set-Content -Path CLAUDE.md -Value x"`, true},
		{`pwsh -c "Add-Content .\CLAUDE.md x"`, true},
		{`powershell -Command "Add-Content notes.txt '- reviewed'"`, false},
		{`powershell -Command "Get-Content CLAUDE.md"`, false},
		{`powershell -Command "Write-Output CLAUDE.md"`, false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
			ctx := authenticatedClaudeCodeTestContext()
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "InstructionsLoaded", SessionID: "pwshbody", CWD: project, FilePath: file})
			response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "pwshbody", CWD: project, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": tc.command},
			})
			if got := response.Action == guardrailActionBlock; got != tc.block ||
				tc.block && !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("action=%q findings=%v reason=%q, want block=%v", response.Action, response.Findings, response.Reason, tc.block)
			}
		})
	}
}
