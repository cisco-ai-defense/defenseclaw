// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1982: the plain reading of a Windows command (the Git Bash and cmd
// grammar) read a PowerShell comment as words, so a project write followed
// by a comment that names ~/.ssh/authorized_keys was denied in Codex action
// mode. In a call the hook reads as PowerShell (or POSIX), a comment that
// Git Bash and PowerShell both skip, and through which cmd cannot reach a
// file, is skipped there too; a call of unknown dialect keeps every word
// (TestR104WindowsActionExplicitDialect). The escaped forms (a #
// after a backtick-escaped blank), writes before or after a comment, and
// comment text that cmd would run or expand keep blocking.
func TestGAP1982PowerShellCommentNamingAProtectedPath(t *testing.T) {
	const home, cwd = `C:\Users\alice`, `C:\Users\alice\oo-proj`
	installDefaultProfileConnector(t, "codex")
	for _, row := range []struct {
		command string
		block   bool
	}{
		{"Set-Content notes.txt x", false},
		{"Set-Content notes.txt x # see ~/.ssh/authorized_keys", false},
		{`Add-Content -Path notes.md -Value done  # do not edit ~\.ssh\authorized_keys`, false},
		{"# rotate ~/.ssh/authorized_keys later\nSet-Content notes.txt x", false},
		{"Set-Content ~/.ssh/authorized_keys x", true},
		{"echo dummy-key >> ~/.ssh/authorized_keys", true},
		{"Set-Content ~/.ssh/authorized_keys x # see notes", true},
		{"# notes\nSet-Content ~/.ssh/authorized_keys x", true},
		{"Write-Output a` #; Set-Content ~\\.ssh\\authorized_keys k", true},
		{"Write-Output a` #; Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k", true},
		{"Write-Output a` #; echo k >> ~\\.ssh\\authorized_keys", true},
		{"echo a\r#x; cp k.pub ~/.ssh/authorized_keys", true},
		{"Set-Content notes.txt x # & echo k >> %USERPROFILE%\\.ssh\\authorized_keys", true},
		{`python w.py # C:\Users\alice\.ssh\authorized_keys`, true},
	} {
		args, err := json.Marshal(map[string]string{"command": row.command})
		if err != nil {
			t.Fatal(err)
		}
		// The dialect the Codex hook picks on Windows (codex_hook.go).
		input := actionfacts.Input{Tool: "shell_command", Args: args, CWD: cwd, ActiveHome: home}
		input.DialectHint = selectWindowsShellDialect("shell_command", row.command, input)
		if !row.block && input.DialectHint != actionfacts.DialectPowerShell {
			t.Fatalf("%q: hook dialect %q, want powershell", row.command, input.DialectHint)
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, LegacyText: string(args),
			Connector: "codex", EnforcementCapable: true})
		if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
			t.Errorf("hint=%q %q: block=%v, want %v (%v)", input.DialectHint, row.command, blocked, row.block, FindingStrings(findings))
		}
	}
}
