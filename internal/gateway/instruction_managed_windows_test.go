// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// On managed Windows hosts the gateway checks the call-time file identity
// itself. The native hook supplies the startup snapshot but no pre-tool path
// evidence, so a loaded file must still block and a replacement must not.
func TestInstructionProtectionManagedCodexWindowsCallTimeIdentity(t *testing.T) {
	project := t.TempDir()
	file := filepath.Join(project, "AGENTS.md")
	if err := os.WriteFile(file, []byte("startup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	base := withManagedHookPeer(withAuthenticatedHookConnector(t.Context(), "codex"),
		managedHookPeer{Home: project})
	startFacts := map[string]string{
		hookpaths.StartupFilesKey: string(mustJSON(t, map[string]string{file: hookpaths.FileIdentity(file)})),
	}
	api.evaluateCodexHook(context.WithValue(base, resolvedWritesContextKey{}, startFacts), codexHookRequest{
		HookEventName: "SessionStart", SessionID: "loaded", CWD: project,
	})
	call := func() codexHookResponse {
		return api.evaluateCodexHook(base, codexHookRequest{
			HookEventName: "PreToolUse", SessionID: "loaded", CWD: project,
			ToolName: "exec_command", ToolInput: map[string]interface{}{
				"cmd": "Add-Content -LiteralPath 'AGENTS.md' -Value x",
			},
		})
	}
	if got := call(); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
		t.Fatalf("loaded Windows instruction was not protected: %+v", got)
	}
	if err := os.Rename(file, filepath.Join(project, "saved.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := call(); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("replacement inherited loaded Windows identity: %+v", got)
	}
}
