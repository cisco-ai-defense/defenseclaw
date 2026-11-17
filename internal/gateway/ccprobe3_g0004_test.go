// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe3 old-API probe for rel-1-0-10:GAP-0004 (P2 false block, Windows):
// the Codex hook route (evaluateCodexHook, old API at the pre-fix sha
// a81914bd31 = 7c3cfc1597^) on native Windows, cwd = the account home: a cat
// here-document whose body is the apply_patch banner lines is text, not an
// authorized_keys command. The home is a temp profile with .ssh in it, so the
// banner word *** can only match .ssh by the Windows glob scan. Windows only:
// on Linux the same call is allowed on both sides (s7-probe1 NO-RED).
// Scratch, test-only branch s7/ccprobes-3.

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestCCP3GAP0004CodexHeredocBannerAtHomeIsAllowedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows glob scan of a here-document body runs on native Windows only")
	}
	home := filepath.Join(t.TempDir(), "b00")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	const command = "cat <<\"EOT\"\n*** Begin Patch\n*** End Patch\nEOT"
	for _, posture := range []string{"default", "permissive"} {
		const connector = "codex"
		installToolCallCorpusProfileConnector(t, connector, posture)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connector
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
		response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
			HookEventName: "PreToolUse",
			ToolName:      "shell",
			CWD:           home,
			ToolInput:     map[string]interface{}{"command": command},
		})
		t.Logf("ROW codex/%s cwd=home: %s %s %v", posture, response.Action, response.Severity, response.Findings)
		if response.Action == "block" {
			t.Errorf("codex/%s cwd=home: action %q findings %v, want no block for a here-document banner", posture, response.Action, response.Findings)
		}
	}
}
