// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A native Copilot shell call that feeds apply_patch a PowerShell here-string
// naming an absolute project file is an ordinary project edit (T12b Windows
// native run, dc-fc-r103-a4-win1 2026-10-25).
func TestNativeCopilotShellPatchHereString(t *testing.T) {
	project := t.TempDir()
	for _, tc := range []struct{ name, tool, command string }{
		{"powershell here-string absolute", "powershell", "apply_patch @'\n*** Begin Patch\n*** Add File: " + filepath.Join(project, "notes-cp2.txt") + "\n+T12b loop 1 absolute path edit.\n*** End Patch\n'@"},
		{"powershell here-string relative", "powershell", "apply_patch @'\n*** Begin Patch\n*** Add File: notes-cp2.txt\n+T12b loop 1 relative path edit.\n*** End Patch\n'@"},
		{"powershell here-string nested relative", "powershell", "apply_patch @'\n*** Begin Patch\n*** Add File: src/notes-cp2.txt\n+edit\n*** Update File: " + filepath.Join(project, "README.md") + "\n@@\n-old\n+new\n*** End Patch\n'@"},
		{"bash heredoc absolute", "bash", "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: " + filepath.Join(project, "notes-cp2.txt") + "\n+edit\n*** End Patch\nEOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tool == "bash" && runtime.GOOS == "windows" {
				t.Skip("Copilot CLI on Windows runs PowerShell; the Windows grammar does not read POSIX heredocs")
			}
			body, err := json.Marshal(map[string]any{"sessionId": "native-shell-patch", "cwd": project,
				"toolCalls": []any{map[string]any{"id": "call_shell_patch", "name": tc.tool,
					"args": map[string]any{"command": tc.command, "description": "Create requested notes file"}}}})
			if err != nil {
				t.Fatal(err)
			}
			action, response := postHookDecision(t, "copilot", "", string(body))
			if action != "allow" || strings.Contains(response, hookToolCallUnparsedRuleID) {
				t.Fatalf("action=%s: %s", action, response)
			}
		})
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, tc := range []struct{ name, command string }{
		{"protected target", "apply_patch @'\n*** Begin Patch\n*** Add File: " + keys + "\n+ssh-ed25519 AAAA attacker\n*** End Patch\n'@"},
		{"protected target behind a project file", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+a\n*** Add File: " + keys + "\n+ssh-ed25519 AAAA attacker\n*** End Patch\n'@"},
		{"expanding here-string", "apply_patch @\"\n*** Begin Patch\n*** Add File: notes.txt\n+$keys\n*** End Patch\n\"@"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"sessionId": "native-shell-patch", "cwd": project,
				"toolCalls": []any{map[string]any{"id": "call_shell_patch", "name": "powershell",
					"args": map[string]any{"command": tc.command, "description": "Create requested notes file"}}}})
			if err != nil {
				t.Fatal(err)
			}
			action, response := postHookDecision(t, "copilot", "", string(body))
			if tc.name != "expanding here-string" && action != "block" {
				t.Fatalf("protected patch through PowerShell action=%s: %s", action, response)
			}
			if tc.name == "expanding here-string" && runtime.GOOS == "windows" && action != "block" {
				t.Fatalf("expanding here-string action=%s: %s", action, response)
			}
		})
	}
}
