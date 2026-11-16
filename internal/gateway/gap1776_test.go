// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-1776: after an earlier cd a relative Git Bash operand is not in the
// hook cwd, so it is not placed there; a rooted operand still is.
func TestR105GAP1776RelativeOperandAfterCdIsNotPlaced(t *testing.T) {
	cwd, home := `C:\Users\alice\proj`, `C:\Users\alice`
	for _, tc := range []struct{ value, want string }{
		{"CLAUDE.md", ""},
		{"./CLAUDE.md", ""},
		{"../proj/CLAUDE.md", ""},
		{`C:\Users\alice\proj\CLAUDE.md`, "C:/Users/alice/proj/CLAUDE.md"},
		{"/c/Users/alice/proj/CLAUDE.md", "C:/Users/alice/proj/CLAUDE.md"},
		{"~/proj/CLAUDE.md", "C:/Users/alice/proj/CLAUDE.md"},
	} {
		got, ok := windowsHostPathOfPOSIXOperand(tc.value, cwd, home, true)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%q: got %q %v, want %q", tc.value, got, ok, tc.want)
		}
	}
}

// GAP-1776 (P3, native Windows): `cd sub && echo x > CLAUDE.md` from the
// Claude Code Bash tool (Git Bash) writes sub/CLAUDE.md, which the session
// did not load: it is ordinary. The loaded CLAUDE.md named by a rooted path
// after the same cd still blocks.
func TestR105GAP1776WindowsGitBashWriteAfterCd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows host paths")
	}
	project := instructionIdentityTestRoot(t)
	file := writeActiveAgentTestFile(t, project, "CLAUDE.md")
	if err := os.MkdirAll(filepath.Join(project, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	msys := "/" + strings.ToLower(file[:1]) + filepath.ToSlash(file[2:])
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{"cd sub && echo x > CLAUDE.md", false},
		{"cd sub; printf x >> ./CLAUDE.md", false},
		{"pushd sub && echo x > CLAUDE.md", false},
		{"echo x > CLAUDE.md", true},
		{"cd sub && echo x > " + filepath.ToSlash(file), true},
		{"cd sub && echo x > " + msys, true},
		{"echo ok > notes.txt && cd sub && echo y > CLAUDE.md", false},
		{"echo x > CLAUDE.md && cd sub", true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
			ctx := authenticatedClaudeCodeTestContext()
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "InstructionsLoaded", SessionID: "gitbashcd", CWD: project, FilePath: file})
			response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gitbashcd", CWD: project, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": tc.command},
			})
			if got := response.Action == guardrailActionBlock; got != tc.block ||
				tc.block && !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("action=%q findings=%v reason=%q, want block=%v", response.Action, response.Findings, response.Reason, tc.block)
			}
		})
	}
}
