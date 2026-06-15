// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// TestHookInvocationCommand pins the platform split: Unix runs the bundled .sh
// path; Windows invokes the native Go `hook` subcommand instead of any Bash/.cmd
// wrapper.
func TestHookInvocationCommand(t *testing.T) {
	const unix = "/home/u/.defenseclaw/hooks/codex-hook.sh"

	for _, goos := range []string{"linux", "darwin"} {
		if got := hookInvocationCommandFor(goos, "codex", unix); got != unix {
			t.Errorf("%s command = %q, want passthrough %q", goos, got, unix)
		}
	}

	win := hookInvocationCommandFor("windows", "cursor", unix)
	if !strings.Contains(win, nativeHookFlag+"cursor") {
		t.Errorf("windows command = %q, missing %q", win, nativeHookFlag+"cursor")
	}
	if strings.Contains(win, ".sh") || strings.Contains(win, ".cmd") || strings.Contains(win, "bash") {
		t.Errorf("windows command = %q should not reference a shell/script wrapper", win)
	}
	if !isNativeHookCommand(win) {
		t.Errorf("isNativeHookCommand(%q) = false, want true", win)
	}
	if isNativeHookCommand(unix) {
		t.Errorf("isNativeHookCommand(%q) = true, want false for a .sh path", unix)
	}
}

// TestShellWordPassesNativeCommandThrough ensures the bash-style quoter does not
// corrupt the native Windows command (which is already a complete command line)
// while still quoting Unix script paths for the agent's shell.
func TestShellWordPassesNativeCommandThrough(t *testing.T) {
	native := `"C:\dc.exe" hook --connector cursor`
	if got := shellWord(native); got != native {
		t.Errorf("shellWord(native) = %q, want unchanged", got)
	}
	if got := shellWord("/home/u/hooks/cursor-hook.sh"); got != "'/home/u/hooks/cursor-hook.sh'" {
		t.Errorf("shellWord(path) = %q, want single-quoted", got)
	}
}

// TestBuildCodexHooksTableHashesTheCommand verifies the Codex hooks table writes
// the trust hash over the exact command it executes (so Codex recognizes it),
// and that teardown reproduces the same fingerprint to remove the state.
func TestBuildCodexHooksTableHashesTheCommand(t *testing.T) {
	const cmd = `"C:\Program Files\defenseclaw\defenseclaw-gateway.exe" hook --connector codex`
	const configPath = "/home/u/.codex/config.toml"

	table := buildCodexHooksTable(configPath, cmd)

	for _, group := range codexHookGroups {
		raw, ok := table[group.eventType].([]interface{})
		if !ok || len(raw) == 0 {
			t.Fatalf("missing event %s", group.eventType)
		}
		mg := raw[0].(map[string]interface{})
		hooks := mg["hooks"].([]interface{})
		h0 := hooks[0].(map[string]interface{})
		if got := h0["command"].(string); got != cmd {
			t.Errorf("event %s command = %q, want %q", group.eventType, got, cmd)
		}
	}

	state, ok := table["state"].(map[string]interface{})
	if !ok || len(state) == 0 {
		t.Fatal("expected non-empty state table")
	}

	// Teardown with the same command recognizes and removes every entry.
	hooks := map[string]interface{}{"state": state}
	if !removeOwnedCodexHookState(hooks, configPath, cmd) {
		t.Fatal("removeOwnedCodexHookState did not recognize its own hash")
	}
	if _, present := hooks["state"]; present {
		t.Error("state should be deleted once every owned entry is removed")
	}

	// A different command must NOT match (ownership specificity).
	fresh := buildCodexHooksTable(configPath, cmd)
	freshHooks := map[string]interface{}{"state": fresh["state"]}
	if removeOwnedCodexHookState(freshHooks, configPath, `"other.exe" hook --connector codex`) {
		t.Error("teardown removed state for a command it never wrote")
	}
}

// TestIsOwnedHookRecognizesNativeCommand covers the Claude Code / hook teardown
// recognizer for the native Windows command, which is not a file path under the
// hooks dir and carries no on-disk marker.
func TestIsOwnedHookRecognizesNativeCommand(t *testing.T) {
	const hooksDir = "/home/u/.defenseclaw/hooks"

	owned := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": `"C:\dc.exe" hook --connector claudecode`,
			},
		},
	}
	if !isOwnedHook(owned, hooksDir) {
		t.Error("native hook command not recognized as DefenseClaw-owned")
	}

	foreign := map[string]interface{}{
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": "/usr/bin/some-other-tool --flag"},
		},
	}
	if isOwnedHook(foreign, hooksDir) {
		t.Error("foreign command wrongly recognized as DefenseClaw-owned")
	}
}
