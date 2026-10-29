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

const (
	sightingUpdatePatch = "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-x\n+new\n*** End Patch"
	sightingAddPatch    = "*** Begin Patch\n*** Add File: AGENTS.md\n+new\n*** End Patch"
)

// A managed gateway cannot read the user's files, so the managed hook client
// sends the first sighting of every directory a call reaches, an empty one
// included. A file a managed session creates in a directory it reached after
// it started is then its own file there, also after a gateway restart, while
// a file that was already there stays protected.
func TestInstructionProtectionManagedSessionReachesNewDirectory(t *testing.T) {
	first, second, third := t.TempDir(), t.TempDir(), t.TempDir()
	writeActiveAgentTestFile(t, third, "AGENTS.md")
	dataDir := t.TempDir()
	newGateway := func(mode string) *APIServer {
		api := instructionProtectionTestAPI(t, "codex", mode, "HIGH")
		api.scannerCfg.DataDir = dataDir
		return api
	}
	peer := managedHookPeer{Home: first}
	start := mustJSON(t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "live", "cwd": first})
	startFacts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", start))
	if !ok {
		t.Fatal("managed hook did not send startup identity evidence")
	}
	api := newGateway("action")
	api.evaluateCodexHook(withManagedHookPeer(withAuthenticatedHookConnector(
		context.WithValue(t.Context(), resolvedWritesContextKey{}, startFacts), "codex"), peer),
		codexHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: first})
	call := func(api *APIServer, cwd, patch string) codexHookResponse {
		t.Helper()
		input := map[string]interface{}{"command": patch}
		ctx := withManagedHookPeer(withAuthenticatedHookConnector(
			instructionResolvedWriteContext(t, cwd, "apply_patch", input), "codex"), peer)
		return api.evaluateCodexHook(ctx, codexHookRequest{
			HookEventName: "PreToolUse", SessionID: "live", CWD: cwd, ToolName: "apply_patch", ToolInput: input,
		})
	}
	if got := call(api, second, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("managed: creating AGENTS.md in a later workdir: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(second, "AGENTS.md"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := call(api, second, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("managed: editing the AGENTS.md this session created in a later workdir: %+v", got)
	}
	if got := call(api, third, sightingUpdatePatch); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
		t.Fatalf("managed: existing AGENTS.md in a later workdir became writable: %+v", got)
	}
	api = newGateway("action")
	if got := call(api, second, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("managed: restart blocked the AGENTS.md this session created: %+v", got)
	}
	if got := call(api, third, sightingUpdatePatch); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
		t.Fatalf("managed: restart made the existing AGENTS.md writable: %+v", got)
	}
	if got := call(newGateway("observe"), third, sightingUpdatePatch); got.Action == guardrailActionBlock {
		t.Fatalf("managed observe mode blocked: %+v", got)
	}
}

// Two spellings of one directory share its first sighting: the session
// reached it through a symlink, or a case variant on a case-insensitive
// volume, and a later call names it another way.
func TestInstructionSnapshotKeepsAnotherSpellingsRecord(t *testing.T) {
	codexCall := func(t *testing.T, api *APIServer, ctx context.Context, cwd, patch string) codexHookResponse {
		t.Helper()
		input := map[string]interface{}{"command": patch}
		callCtx := instructionResolvedWriteContext(t, cwd, "apply_patch", input)
		if peer, managed := managedHookPeerFromContext(ctx); managed {
			callCtx = withManagedHookPeer(callCtx, peer)
		}
		return api.evaluateCodexHook(withAuthenticatedHookConnector(callCtx, "codex"), codexHookRequest{
			HookEventName: "PreToolUse", SessionID: "live", CWD: cwd, ToolName: "apply_patch", ToolInput: input,
		})
	}
	symlinked := func(t *testing.T) (string, string) {
		t.Helper()
		base := t.TempDir()
		physical := filepath.Join(base, "real")
		if err := os.Mkdir(physical, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(physical, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		return link, physical
	}
	for _, managed := range []bool{false, true} {
		name := "per-user"
		if managed {
			name = "managed"
		}
		t.Run(name+" symlink", func(t *testing.T) {
			link, physical := symlinked(t)
			dataDir := t.TempDir()
			newGateway := func() *APIServer {
				api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
				api.scannerCfg.DataDir = dataDir
				return api
			}
			ctx := withAuthenticatedHookConnector(t.Context(), "codex")
			if managed {
				start := mustJSON(t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "live", "cwd": link})
				facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", start))
				if !ok {
					t.Fatal("managed hook did not send startup identity evidence")
				}
				ctx = withManagedHookPeer(context.WithValue(ctx, resolvedWritesContextKey{}, facts),
					managedHookPeer{Home: t.TempDir()})
			}
			newGateway().evaluateCodexHook(ctx, codexHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: link})
			// The session creates AGENTS.md in the directory it started in.
			if err := os.WriteFile(filepath.Join(physical, "AGENTS.md"), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// A new gateway process each time: the directory identities are
			// in the saved record too.
			if got := codexCall(t, newGateway(), ctx, physical, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("the physical spelling made the session's own AGENTS.md pre-existing: %+v", got)
			}
		})
		t.Run(name+" symlink keeps an existing file protected", func(t *testing.T) {
			link, physical := symlinked(t)
			writeActiveAgentTestFile(t, physical, "AGENTS.md")
			api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
			api.scannerCfg.DataDir = t.TempDir()
			ctx := withAuthenticatedHookConnector(t.Context(), "codex")
			if managed {
				start := mustJSON(t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "live", "cwd": link})
				facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", start))
				if !ok {
					t.Fatal("managed hook did not send startup identity evidence")
				}
				ctx = withManagedHookPeer(context.WithValue(ctx, resolvedWritesContextKey{}, facts),
					managedHookPeer{Home: t.TempDir()})
			}
			api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: link})
			if got := codexCall(t, api, ctx, physical, sightingUpdatePatch); got.Action != guardrailActionBlock ||
				!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
				t.Fatalf("the physical spelling made an existing AGENTS.md writable: %+v", got)
			}
		})
	}
	t.Run("case variant", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows directory keys are case folded already")
		}
		base := t.TempDir()
		upper := filepath.Join(base, "Project")
		if err := os.Mkdir(upper, 0o700); err != nil {
			t.Fatal(err)
		}
		lower := filepath.Join(base, "project")
		if _, err := os.Stat(lower); err != nil {
			t.Skip("case-sensitive volume")
		}
		api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
		api.scannerCfg.DataDir = t.TempDir()
		ctx := withAuthenticatedHookConnector(t.Context(), "codex")
		api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: upper})
		if err := os.WriteFile(filepath.Join(upper, "AGENTS.md"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := codexCall(t, api, ctx, lower, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("a case variant made the session's own AGENTS.md pre-existing: %+v", got)
		}
	})
}

// With ~/.openclaw/openclaw.json present, OpenClaw's snapshot survives a
// gateway restart: a TOOLS.md the session created stays editable and the
// existing config file stays protected.
func TestInstructionProtectionOpenClawRestartWithConfigFile(t *testing.T) {
	installToolCallCorpusProfileConnector(t, "openclaw", "default")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := filepath.Join(home, ".openclaw", "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	config := writeActiveAgentTestFile(t, filepath.Join(home, ".openclaw"), "openclaw.json")
	created := filepath.Join(workspace, "TOOLS.md")
	appendTo := func(file string) string {
		if runtime.GOOS == "windows" {
			return "Add-Content -LiteralPath '" + file + "' -Value new"
		}
		return "printf new >> '" + file + "'"
	}
	dataDir := t.TempDir()
	newGateway := func() *APIServer {
		api := testAPIServerWithConfig(t, "action")
		api.scannerCfg.Guardrail.Connector = "openclaw"
		api.scannerCfg.Guardrail.BlockAt = "HIGH"
		api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
		api.scannerCfg.DataDir = dataDir
		return api
	}
	inspect := func(api *APIServer, command string) ToolInspectVerdict {
		t.Helper()
		body := mustJSON(t, map[string]interface{}{
			"tool": "exec", "direction": "tool_call", "session_id": "live",
			"args": map[string]interface{}{"command": command, "workdir": workspace},
		})
		_, verdict := postInspectForConnector(t, api, "openclaw", string(body))
		return verdict
	}
	if got := inspect(newGateway(), appendTo(filepath.Join(workspace, "notes.txt"))); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("first call: %+v", got)
	}
	if err := os.WriteFile(created, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := newGateway()
	if got := inspect(api, appendTo(created)); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("restart with openclaw.json present blocked the TOOLS.md this session created: %+v", got)
	}
	if got := inspect(api, appendTo(config)); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-OPENCLAW-JSON") {
		t.Fatalf("restart made the existing openclaw.json writable: %+v", got)
	}
}
