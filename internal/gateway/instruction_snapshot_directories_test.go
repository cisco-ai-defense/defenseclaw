// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A session's instruction-file snapshot is per directory. The instruction
// files a directory holds when the session first reaches it, by working in
// it or writing to it, stay protected in action mode; a file the session
// creates there afterwards stays ordinary (GAP-1363). Reaching a second
// working directory must not make its existing files writable. ZeptoClaw's
// shell tool names no working directory, so only OpenClaw reaches another.
func TestInstructionProtectionInspectSnapshotPerDirectory(t *testing.T) {
	for _, connectorName := range []string{"openclaw"} {
		t.Run(connectorName, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, connectorName, "default")
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			first := filepath.Join(home, ".openclaw", "workspace")
			second := filepath.Join(t.TempDir(), "second")
			third := filepath.Join(t.TempDir(), "third")
			for _, dir := range []string{first, second, third} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			existing := writeActiveAgentTestFile(t, second, "AGENTS.md")
			writeActiveAgentTestFile(t, second, "SOUL.md")
			created := filepath.Join(second, "TOOLS.md")
			elsewhere := filepath.Join(third, "MEMORY.md")
			appendTo := func(file string) string {
				if runtime.GOOS == "windows" {
					return "Add-Content -LiteralPath '" + file + "' -Value new"
				}
				return "printf new >> '" + file + "'"
			}
			dataDir := t.TempDir()
			newGateway := func(mode string) *APIServer {
				api := testAPIServerWithConfig(t, mode)
				api.scannerCfg.Guardrail.Connector = connectorName
				api.scannerCfg.Guardrail.BlockAt = "HIGH"
				api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
				api.scannerCfg.DataDir = dataDir
				return api
			}
			inspect := func(api *APIServer, workdir, command string) ToolInspectVerdict {
				t.Helper()
				body := mustJSON(t, map[string]interface{}{
					"tool": "exec", "direction": "tool_call", "session_id": "live",
					"args": map[string]interface{}{"command": command, "workdir": workdir},
				})
				_, verdict := postInspectForConnector(t, api, connectorName, string(body))
				return verdict
			}
			blocked := func(got ToolInspectVerdict, rule string) bool {
				return got.Action == guardrailActionBlock && findingStringHasRuleID(got.Findings, rule)
			}
			api := newGateway("action")
			if got := inspect(api, first, appendTo(filepath.Join(first, "notes.txt"))); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("first call: %+v", got)
			}
			if got := inspect(api, second, appendTo(existing)); !blocked(got, "COG-AGENTS-MD") {
				t.Fatalf("existing AGENTS.md in the second workdir became writable: %+v", got)
			}
			if got := inspect(api, second, appendTo(filepath.Join(second, "SOUL.md"))); !blocked(got, "COG-SOUL") {
				t.Fatalf("existing SOUL.md in the second workdir became writable: %+v", got)
			}
			if got := inspect(api, second, appendTo(created)); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("creating TOOLS.md in the second workdir: %+v", got)
			}
			if err := os.WriteFile(created, []byte("new\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := inspect(api, second, appendTo(created)); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("editing the TOOLS.md this session created: %+v", got)
			}
			// A file created in a folder the session reached only by writing
			// to it is the session's own file when it later works there.
			if got := inspect(api, first, appendTo(elsewhere)); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("creating MEMORY.md in another folder: %+v", got)
			}
			if err := os.WriteFile(elsewhere, []byte("new\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := inspect(api, third, appendTo(elsewhere)); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("editing the MEMORY.md this session created: %+v", got)
			}
			api = newGateway("action")
			if got := inspect(api, second, appendTo(existing)); !blocked(got, "COG-AGENTS-MD") {
				t.Fatalf("restart made the existing AGENTS.md writable: %+v", got)
			}
			if got := inspect(api, second, appendTo(created)); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("restart blocked the TOOLS.md this session created: %+v", got)
			}
			if got := inspect(newGateway("observe"), second, appendTo(existing)); got.Action == guardrailActionBlock {
				t.Fatalf("observe mode blocked: %+v", got)
			}
		})
	}
}

// An inspect call of a connector whose hooks took the session's snapshot is
// judged with that same snapshot.
func TestInstructionProtectionInspectSharesHookSnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		// OpenCode's bash tool is read as POSIX; the OpenClaw inspect test
		// above covers the Windows inspect path.
		t.Skip("OpenCode's bash tool takes POSIX commands")
	}
	first, second := t.TempDir(), t.TempDir()
	existing := writeActiveAgentTestFile(t, second, "AGENTS.md")
	api := testAPIServerWithConfig(t, "action")
	installToolCallCorpusProfileConnector(t, "opencode", "default")
	api.scannerCfg.Guardrail.Connector = "opencode"
	api.scannerCfg.Guardrail.BlockAt = "HIGH"
	api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api.scannerCfg.DataDir = t.TempDir()
	api.applyInstructionStartup(withAuthenticatedHookConnector(t.Context(), "opencode"), "opencode", "live", "session.created", first)
	created := filepath.Join(first, "AGENTS.md")
	if err := os.WriteFile(created, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inspect := func(workdir, file string) ToolInspectVerdict {
		t.Helper()
		command := "printf new >> '" + file + "'"
		if runtime.GOOS == "windows" {
			command = "Add-Content -LiteralPath '" + file + "' -Value new"
		}
		body := mustJSON(t, map[string]interface{}{
			"tool": "bash", "direction": "tool_call", "session_id": "live",
			"args": map[string]interface{}{"command": command, "workdir": workdir},
		})
		_, verdict := postInspectForConnector(t, api, "opencode", string(body))
		return verdict
	}
	if got := inspect(first, created); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("inspect blocked the AGENTS.md this session created: %+v", got)
	}
	if got := inspect(second, existing); got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
		t.Fatalf("inspect made an existing AGENTS.md writable: %+v", got)
	}
}

func TestInstructionProtectionHookSnapshotPerDirectory(t *testing.T) {
	t.Run("codex", func(t *testing.T) {
		first, second, third := t.TempDir(), t.TempDir(), t.TempDir()
		writeActiveAgentTestFile(t, second, "AGENTS.md")
		dataDir := t.TempDir()
		newGateway := func() *APIServer {
			api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
			api.scannerCfg.DataDir = dataDir
			return api
		}
		api := newGateway()
		auth := withAuthenticatedHookConnector(t.Context(), "codex")
		api.evaluateCodexHook(auth, codexHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: first})
		update := map[string]interface{}{
			"command": "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-x\n+new\n*** End Patch",
		}
		add := map[string]interface{}{
			"command": "*** Begin Patch\n*** Add File: AGENTS.md\n+new\n*** End Patch",
		}
		call := func(api *APIServer, cwd string, input map[string]interface{}) codexHookResponse {
			ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, cwd, "apply_patch", input), "codex")
			return api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", SessionID: "live", CWD: cwd, ToolName: "apply_patch", ToolInput: input,
			})
		}
		if got := call(api, second, update); got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
			t.Fatalf("existing AGENTS.md in the second workdir became writable: %+v", got)
		}
		if got := call(api, third, add); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("creating AGENTS.md in the third workdir: %+v", got)
		}
		if err := os.WriteFile(filepath.Join(third, "AGENTS.md"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := call(api, third, update); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("editing the AGENTS.md this session created: %+v", got)
		}
		api = newGateway()
		if got := call(api, second, update); got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
			t.Fatalf("restart made the existing AGENTS.md writable: %+v", got)
		}
		if got := call(api, third, update); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("restart blocked the AGENTS.md this session created: %+v", got)
		}
	})
	t.Run("claude code after CwdChanged", func(t *testing.T) {
		first, second := t.TempDir(), t.TempDir()
		existing := writeActiveAgentTestFile(t, second, "CLAUDE.md")
		api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
		api.scannerCfg.DataDir = t.TempDir()
		auth := withAuthenticatedHookConnector(t.Context(), "claudecode")
		api.evaluateClaudeCodeHook(auth, claudeCodeHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: first})
		api.evaluateClaudeCodeHook(auth, claudeCodeHookRequest{HookEventName: "CwdChanged", SessionID: "live", CWD: second})
		input := map[string]interface{}{"file_path": existing, "content": "changed\n"}
		ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, second, "Write", input), "claudecode")
		got := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "live", CWD: second, ToolName: "Write", ToolInput: input,
		})
		if got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-CLAUDE-MD") {
			t.Fatalf("existing CLAUDE.md in the new workdir became writable: %+v", got)
		}
	})
	t.Run("managed codex", func(t *testing.T) {
		first, second := t.TempDir(), t.TempDir()
		writeActiveAgentTestFile(t, second, "AGENTS.md")
		api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
		api.scannerCfg.DataDir = t.TempDir()
		body := mustJSON(t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "live", "cwd": first})
		facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", body))
		if !ok {
			t.Fatal("managed hook did not send startup identity evidence")
		}
		peer := managedHookPeer{Home: first}
		api.evaluateCodexHook(withManagedHookPeer(withAuthenticatedHookConnector(
			context.WithValue(t.Context(), resolvedWritesContextKey{}, facts), "codex"), peer),
			codexHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: first})
		input := map[string]interface{}{
			"command": "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-x\n+new\n*** End Patch",
		}
		ctx := withManagedHookPeer(withAuthenticatedHookConnector(
			instructionResolvedWriteContext(t, second, "apply_patch", input), "codex"), peer)
		got := api.evaluateCodexHook(ctx, codexHookRequest{
			HookEventName: "PreToolUse", SessionID: "live", CWD: second, ToolName: "apply_patch", ToolInput: input,
		})
		if got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
			t.Fatalf("managed: existing AGENTS.md outside the start workdir became writable: %+v", got)
		}
	})
}

// The generic agent hooks (OpenCode here) take the same per-directory
// snapshot on a tool call in a new working directory, and a mid-session
// session.error neither ends it nor re-takes it.
func TestInstructionStartupAgentHookReachesNewDirectory(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	existing := writeActiveAgentTestFile(t, second, "AGENTS.md")
	api := instructionProtectionTestAPI(t, "opencode", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	auth := withAuthenticatedHookConnector(t.Context(), "opencode")
	api.applyInstructionStartup(auth, "opencode", "live", "session.created", first)
	api.applyInstructionStartup(auth, "opencode", "live", "session.error", first)
	created := filepath.Join(first, "AGENTS.md")
	if err := os.WriteFile(created, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flavor := actionfacts.PathFlavorPOSIX
	if runtime.GOOS == "windows" {
		flavor = actionfacts.PathFlavorWindows
	}
	got := api.applyInstructionStartup(auth, "opencode", "live", "tool.execute.before", second)
	key, _ := activeAgentInstructionPath(existing, flavor)
	if !got.startupKnown || got.startupFiles[key] == "" {
		t.Fatalf("tool call in a new workdir did not record its AGENTS.md: %+v", got)
	}
	api.applyInstructionStartup(auth, "opencode", "live", "session.error", second)
	got = api.applyInstructionStartup(auth, "opencode", "live", "tool.execute.before", first)
	createdKey, _ := activeAgentInstructionPath(created, flavor)
	if !got.startupKnown || got.startupFiles[key] == "" || got.startupFiles[createdKey] != "" {
		t.Fatalf("session.error changed the snapshot: %+v", got)
	}
}
