// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A managed gateway may have no filesystem access to the caller's home.
// The authenticated hook client's startup and write identities still prove
// that the native Codex session loaded the AGENTS.md it is about to edit.
func TestInstructionProtectionManagedCodexLoadedStartupShell(t *testing.T) {
	project := filepath.Join(t.TempDir(), "private-project")
	file := filepath.Join(project, "AGENTS.md")
	const identity = "a:b"
	// These wire keys are literal so the regression compiles at the
	// 47d8c9c79a baseline, before the startup-identity code existed.
	const startupFilesKey = "\x00startup-instructions"
	const writeIdentityPrefix = "\x00write-identity:"
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	base := withManagedHookPeer(withAuthenticatedHookConnector(t.Context(), "codex"),
		managedHookPeer{Home: filepath.Dir(project)})
	startFacts := map[string]string{
		startupFilesKey: string(mustJSON(t, map[string]string{file: identity})),
	}
	api.evaluateCodexHook(context.WithValue(base, resolvedWritesContextKey{}, startFacts), codexHookRequest{
		HookEventName: "SessionStart", SessionID: "loaded", CWD: project,
	})
	input := map[string]interface{}{"cmd": "printf x >> AGENTS.md"}
	writeFacts := map[string]string{
		hookpaths.CWDKey:           project,
		file:                       file,
		writeIdentityPrefix + file: identity,
	}
	response := api.evaluateCodexHook(context.WithValue(base, resolvedWritesContextKey{}, writeFacts), codexHookRequest{
		HookEventName: "PreToolUse", SessionID: "loaded", CWD: project,
		ToolName: "exec_command", ToolInput: input,
	})
	if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-AGENTS-MD") {
		t.Fatalf("loaded Codex startup file was allowed in managed action mode: %+v", response)
	}
}
