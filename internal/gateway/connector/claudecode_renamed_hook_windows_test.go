// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"path/filepath"
	"testing"
)

// GAP-1364: setup and remove drop an edited Claude Code handler that keeps
// DefenseClaw's argv in DefenseClaw's bin directory, and keep a foreign one.
func TestRemoveOwnedClaudeCodeHooksDropsRenamedLauncher(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	defer PinNativeHookExecutableForTest(filepath.Join(binDir, "defenseclaw-hook.exe"))()
	foreignDir := t.TempDir()

	handler := func(command string) map[string]interface{} {
		return map[string]interface{}{
			"type":    "command",
			"command": command,
			"args":    []interface{}{"hook", "--connector", "claudecode"},
			"timeout": 30,
		}
	}
	groups := []interface{}{
		map[string]interface{}{"hooks": []interface{}{
			handler(filepath.Join(binDir, "defenseclaw-hook-renamed.exe")),
			handler(filepath.Join(binDir, "defenseclaw-hook.exe")),
			handler(filepath.Join(foreignDir, "defenseclaw-hook-renamed.exe")),
		}},
	}
	remaining, err := removeOwnedClaudeCodeHooks(groups, filepath.Join(t.TempDir(), "hooks"), nil)
	if err != nil {
		t.Fatalf("removeOwnedClaudeCodeHooks: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("remaining groups = %#v, want only the foreign handler", remaining)
	}
	kept := remaining[0].(map[string]interface{})["hooks"].([]interface{})
	if len(kept) != 1 || kept[0].(map[string]interface{})["command"] != filepath.Join(foreignDir, "defenseclaw-hook-renamed.exe") {
		t.Fatalf("kept handlers = %#v, want only the foreign-directory handler", kept)
	}
}
