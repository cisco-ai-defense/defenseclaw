// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A file created by a running session was absent when the agent loaded its
// startup instructions. Its next edit is still ordinary file work. A new
// session does load that file and must protect it.
func TestInstructionProtectionCodexCreationStaysWritableUntilNextSession(t *testing.T) {
	for _, tc := range []struct {
		name, tool string
		input      map[string]interface{}
	}{
		{"apply patch", "apply_patch", map[string]interface{}{
			"command": "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-old\n+new\n*** End Patch",
		}},
		{"exec patch", "exec_command", map[string]interface{}{
			"cmd": "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-old\n+new\n*** End Patch\nPATCH",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := t.TempDir()
			dataDir := t.TempDir()
			newGateway := func() *APIServer {
				api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
				api.scannerCfg.DataDir = dataDir
				return api
			}
			api := newGateway()
			auth := withAuthenticatedHookConnector(t.Context(), "codex")
			api.evaluateCodexHook(auth, codexHookRequest{
				HookEventName: "SessionStart", SessionID: "first", CWD: project,
			})
			call := func(api *APIServer, session string) codexHookResponse {
				ctx := withAuthenticatedHookConnector(
					instructionResolvedWriteContext(t, project, tc.tool, tc.input), "codex")
				return api.evaluateCodexHook(ctx, codexHookRequest{
					HookEventName: "PreToolUse", SessionID: session, CWD: project,
					ToolName: tc.tool, ToolInput: tc.input,
				})
			}
			if got := call(api, "first"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("first write of absent AGENTS.md: %+v", got)
			}
			if err := os.WriteFile(filepath.Join(project, "AGENTS.md"), []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := call(api, "first"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("next edit in the same session: %+v", got)
			}
			api = newGateway()
			if got := call(api, "first"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("next edit after gateway restart: %+v", got)
			}
			api.evaluateCodexHook(auth, codexHookRequest{
				HookEventName: "SessionStart", SessionID: "second", CWD: project,
			})
			if got := call(api, "second"); got.Action != guardrailActionBlock ||
				!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
				t.Fatalf("new session did not protect loaded AGENTS.md: %+v", got)
			}
		})
	}
}

func TestInstructionProtectionManagedStartupUsesClientSnapshot(t *testing.T) {
	project := t.TempDir()
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	start := func(session string) {
		t.Helper()
		body := mustJSON(t, map[string]interface{}{
			"hook_event_name": "SessionStart", "session_id": session, "cwd": project,
		})
		facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", body))
		if !ok {
			t.Fatal("managed hook did not send startup identity evidence")
		}
		ctx := withManagedHookPeer(
			withAuthenticatedHookConnector(context.WithValue(t.Context(), resolvedWritesContextKey{}, facts), "codex"),
			managedHookPeer{Home: project})
		api.evaluateCodexHook(ctx, codexHookRequest{
			HookEventName: "SessionStart", SessionID: session, CWD: project,
		})
		// The state of a managed session is keyed by its verified caller.
		key, _ := instructionStartupKey(ctx, "codex", session)
		if got := api.activeAgentContext.snapshotKey(key); !got.startupKnown {
			t.Fatal("managed gateway lost client startup snapshot")
		}
	}
	start("first")
	file := filepath.Join(project, "AGENTS.md")
	if err := os.WriteFile(file, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := map[string]interface{}{
		"command": "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-old\n+new\n*** End Patch",
	}
	call := func(session string) codexHookResponse {
		ctx := withManagedHookPeer(withAuthenticatedHookConnector(
			instructionResolvedWriteContext(t, project, "apply_patch", input), "codex"),
			managedHookPeer{Home: project})
		return api.evaluateCodexHook(ctx, codexHookRequest{
			HookEventName: "PreToolUse", SessionID: session, CWD: project,
			ToolName: "apply_patch", ToolInput: input,
		})
	}
	if got := call("first"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("managed session blocked file created after start: %+v", got)
	}
	start("second")
	if got := call("second"); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
		t.Fatalf("managed next session missed startup file: %+v", got)
	}
}

func TestInstructionProtectionStartupIdentityAndAuthenticatedLoad(t *testing.T) {
	project := t.TempDir()
	file := filepath.Join(project, "CLAUDE.md")
	api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	auth := withAuthenticatedHookConnector(t.Context(), "claudecode")
	api.evaluateClaudeCodeHook(auth, claudeCodeHookRequest{
		HookEventName: "SessionStart", SessionID: "first", CWD: project,
	})
	call := func(api *APIServer, session string) claudeCodeHookResponse {
		input := map[string]interface{}{"file_path": file, "content": "changed\n"}
		ctx := withAuthenticatedHookConnector(
			instructionResolvedWriteContext(t, project, "Write", input), "claudecode")
		return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: session, CWD: project,
			ToolName: "Write", ToolInput: input,
		})
	}
	if got := call(api, "first"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("absent Claude instruction was blocked: %+v", got)
	}
	if err := os.WriteFile(file, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := call(api, "first"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("created Claude instruction was blocked before load: %+v", got)
	}
	api.evaluateClaudeCodeHook(auth, claudeCodeHookRequest{
		HookEventName: "CwdChanged", SessionID: "first", CWD: project,
	})
	if got := call(api, "first"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("cwd refresh treated a same-session creation as a load: %+v", got)
	}
	afterChange := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	afterChange.scannerCfg.DataDir = api.scannerCfg.DataDir
	if got := call(afterChange, "first"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("restart after cwd refresh lost the startup absence: %+v", got)
	}
	api = afterChange
	api.evaluateClaudeCodeHook(auth, claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded", SessionID: "first", FilePath: file,
	})
	if got := call(api, "first"); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-CLAUDE-MD") {
		t.Fatalf("authenticated load did not protect file: %+v", got)
	}
	restarted := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	restarted.scannerCfg.DataDir = api.scannerCfg.DataDir
	if got := call(restarted, "first"); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-CLAUDE-MD") {
		t.Fatalf("authenticated load lost across restart: %+v", got)
	}
}

func TestInstructionProtectionReplacedStartupFileHasNewIdentity(t *testing.T) {
	project := t.TempDir()
	file := filepath.Join(project, "AGENTS.md")
	if err := os.WriteFile(file, []byte("startup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	auth := withAuthenticatedHookConnector(t.Context(), "codex")
	api.evaluateCodexHook(auth, codexHookRequest{
		HookEventName: "SessionStart", SessionID: "first", CWD: project,
	})
	input := map[string]interface{}{"command": "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-startup\n+changed\n*** End Patch"}
	call := func() codexHookResponse {
		ctx := withAuthenticatedHookConnector(
			instructionResolvedWriteContext(t, project, "apply_patch", input), "codex")
		return api.evaluateCodexHook(ctx, codexHookRequest{
			HookEventName: "PreToolUse", SessionID: "first", CWD: project,
			ToolName: "apply_patch", ToolInput: input,
		})
	}
	if got := call(); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
		t.Fatalf("startup file was not protected: %+v", got)
	}
	if err := os.Rename(file, filepath.Join(project, "saved.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := call(); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("replacement file inherited old identity: %+v", got)
	}
}
