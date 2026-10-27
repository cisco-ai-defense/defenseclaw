// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2130: Claude Code sends SessionStart and InstructionsLoaded at once, so
// the load of an @include (persona/SOUL.md, a symlink to persona-src/soul.txt)
// can be judged before the start. The start of that session is its own
// start, not a new generation: the load stands, so the included file stays
// protected under its link name and its real name, also when the gateway
// restarts between the events. Benign control: a file the load does not
// name stays writable. A start that does not say it is a new session still
// begins a new generation (TestClaudeCodeActiveAgentFilesLifecycleClears).
func TestR105GAP2130LoadBeforeSessionStartKeepsTheInclude(t *testing.T) {
	for _, source := range []string{"startup", "Startup"} {
		for _, restart := range []bool{false, true} {
			name := "source " + source
			if restart {
				name += ", restarts between events"
			}
			t.Run(name, func(t *testing.T) {
				root := instructionIdentityTestRoot(t)
				project := filepath.Join(root, "project")
				writeActiveAgentTestFile(t, project, "CLAUDE.md")
				real := filepath.Join(project, "persona-src", "soul.txt")
				if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(real, []byte("# Soul\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				loaded := filepath.Join(project, "persona", "SOUL.md")
				if err := os.MkdirAll(filepath.Dir(loaded), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join("..", "persona-src", "soul.txt"), loaded); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				dataDir := t.TempDir()
				api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
				api.scannerCfg.DataDir = dataDir
				gateway := func() *APIServer {
					if !restart {
						return api
					}
					next := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
					next.scannerCfg.DataDir = dataDir
					return next
				}
				ctx := authenticatedClaudeCodeTestContext()
				event := func(req claudeCodeHookRequest) claudeCodeHookResponse {
					req.SessionID, req.CWD = "include-first", project
					return gateway().evaluateClaudeCodeHook(ctx, req)
				}
				event(claudeCodeHookRequest{HookEventName: "InstructionsLoaded", FilePath: filepath.Join(project, "CLAUDE.md")})
				event(claudeCodeHookRequest{HookEventName: "InstructionsLoaded", FilePath: loaded})
				event(claudeCodeHookRequest{HookEventName: "SessionStart", Source: source})
				write := func(target string) claudeCodeHookResponse {
					return event(claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Write",
						ToolInput: map[string]interface{}{"file_path": target, "content": "new"}})
				}
				for _, target := range []string{loaded, real} {
					if got := write(target); got.Action != guardrailActionBlock {
						t.Fatalf("the included SOUL.md loaded before the start was writable as %s: %+v", target, got)
					}
				}
				notes := filepath.Join(project, "notes.txt")
				if got := write(notes); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
					t.Fatalf("an unrelated file was blocked: %+v", got)
				}
			})
		}
	}
}
