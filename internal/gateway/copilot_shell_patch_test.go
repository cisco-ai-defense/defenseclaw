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
	piped := func(body string) string { return "@'\n*** Begin Patch\n" + body + "*** End Patch\n'@ | apply_patch" }
	for _, tc := range []struct{ name, tool, command string }{
		{"powershell here-string absolute", "powershell", "apply_patch @'\n*** Begin Patch\n*** Add File: " + filepath.Join(project, "notes-cp2.txt") + "\n+T12b loop 1 absolute path edit.\n*** End Patch\n'@"},
		{"powershell here-string relative", "powershell", "apply_patch @'\n*** Begin Patch\n*** Add File: notes-cp2.txt\n+T12b loop 1 relative path edit.\n*** End Patch\n'@"},
		{"powershell here-string nested relative", "powershell", "apply_patch @'\n*** Begin Patch\n*** Add File: src/notes-cp2.txt\n+edit\n*** Update File: " + filepath.Join(project, "README.md") + "\n@@\n-old\n+new\n*** End Patch\n'@"},
		// Windows only (PowerShell grammar), T12b loop round 2: the piped form
		// and quotes inside the here-string body are the same project write.
		{"powershell piped here-string absolute", "powershell", piped("*** Add File: " + filepath.Join(project, "notes-cp2.txt") + "\n+T12b piped edit.\n")},
		{"powershell piped here-string relative", "powershell", piped("*** Add File: notes-cp2.txt\n+T12b piped edit.\n")},
		{"powershell piped here-string update and move", "powershell", piped("*** Update File: src\\a.ts\n*** Move to: " + filepath.Join(project, "src", "b.ts") + "\n@@\n-a\n+b\n")},
		{"powershell piped here-string then a read", "powershell", piped("*** Add File: notes-cp2.txt\n+x\n") + "; Get-Content notes-cp2.txt"},
		{"powershell here-string with an apostrophe", "powershell", "apply_patch @'\n*** Begin Patch\n*** Add File: notes-cp2.txt\n+It's fine.\n*** End Patch\n'@"},
		{"powershell piped here-string with quotes", "powershell", piped("*** Add File: " + filepath.Join(project, "notes-cp2.txt") + "\n+It's \"fine\".\n")},
		// A literal @'...'@ body expands nothing (T12b round c, loop round 1).
		{"powershell here-string with a literal dollar and backtick", "powershell", "apply_patch @'\n*** Begin Patch\n*** Add File: " + filepath.Join(project, "run.ps1") + "\n+$name = \"x\"\n+Write-Output \"`t$name $(Get-Date)\"\n*** End Patch\n'@"},
		{"powershell piped here-string with a literal dollar and an apostrophe", "powershell", piped("*** Add File: src\\greet.js\n+const greet = (n) => `It's ${n}`;\n")},
		{"bash heredoc absolute", "bash", "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: " + filepath.Join(project, "notes-cp2.txt") + "\n+edit\n*** End Patch\nEOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tool == "bash" && runtime.GOOS == "windows" {
				t.Skip("Copilot CLI on Windows runs PowerShell; the Windows grammar does not read POSIX heredocs")
			}
			if (strings.Contains(tc.name, "piped") || strings.Contains(tc.name, "apostrophe") || strings.Contains(tc.name, "literal")) && runtime.GOOS != "windows" {
				t.Skip("Copilot CLI runs bash on Linux and macOS; a PowerShell pipeline is not a POSIX command")
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
		{"piped protected target", "@'\n*** Begin Patch\n*** Add File: " + keys + "\n+ssh-ed25519 AAAA attacker\n*** End Patch\n'@ | apply_patch"},
		{"protected target behind a project file", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+a\n*** Add File: " + keys + "\n+ssh-ed25519 AAAA attacker\n*** End Patch\n'@"},
		{"piped protected target behind a project file", piped("*** Add File: notes.txt\n+a\n*** Delete File: " + keys + "\n")},
		{"piped protected target with an apostrophe", piped("*** Add File: " + keys + "\n+it's mine\n")},
		{"piped project patch then a protected write", piped("*** Add File: notes.txt\n+a\n") + "; Set-Content -Path " + keys + " -Value k"},
		{"piped project patch then a file-fed patch", piped("*** Add File: notes.txt\n+a\n") + "; Get-Content " + filepath.Join(project, "next.patch") + " | apply_patch"},
		{"protected target with an apostrophe", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+It's\n*** Add File: " + keys + "\n+k\n*** End Patch\n'@"},
		{"protected target beside a literal dollar", "apply_patch @'\n*** Begin Patch\n*** Add File: a.ps1\n+$x = 1\n*** Add File: " + keys + "\n+k\n*** End Patch\n'@"},
		{"piped protected target beside a literal dollar", piped("*** Add File: a.ps1\n+$x\n*** Delete File: " + keys + "\n")},
		{"early Unicode closer then a protected write", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n’@; Set-Content " + keys + " evil; @'\n*** End Patch\n'@"},
		{"lone CR closer then a protected write", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\r'@; Set-Content " + keys + " evil; @'\n*** End Patch\n'@"},
		{"expanding here-string", "apply_patch @\"\n*** Begin Patch\n*** Add File: notes.txt\n+$keys\n*** End Patch\n\"@"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (strings.HasPrefix(tc.name, "early Unicode") || strings.HasPrefix(tc.name, "lone CR")) && runtime.GOOS != "windows" {
				t.Skip("PowerShell here-string terminators apply to Windows Copilot CLI")
			}
			body, err := json.Marshal(map[string]any{"sessionId": "native-shell-patch", "cwd": project,
				"toolCalls": []any{map[string]any{"id": "call_shell_patch", "name": "powershell",
					"args": map[string]any{"command": tc.command, "description": "Create requested notes file"}}}})
			if err != nil {
				t.Fatal(err)
			}
			if (tc.name == "piped project patch then a protected write" || tc.name == "piped project patch then a file-fed patch") && runtime.GOOS != "windows" {
				t.Skip("Set-Content is a PowerShell cmdlet; bash on Linux and macOS has no such writer")
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
