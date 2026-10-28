// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestR105PowerShellToolRouteMatchesBash: a PowerShell-shaped tool call is
// judged like the same text under the Bash tool (GAP-1779, GAP-2389, GAP-1500
// class). Claude Code names the tool PowerShell, Copilot powershell (projected
// to shell by agentHookTrustedActionTool) and Codex shell / shell_command.
func TestR105PowerShellToolRouteMatchesBash(t *testing.T) {
	const connector = "r105-powershell-tool-route"
	installToolCallCorpusProfileConnector(t, connector, "default")
	home := `C:\Users\Alice`
	rows := []struct {
		name, command string
		block         bool
	}{
		{"S1 comment then write", "# update keys\nSet-Content $HOME\\.ssh\\authorized_keys k", true},
		{"S2 Add-Content env", "Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k; Write-Output smartquote-a", true},
		{"S3 smart quote then write", "Write-Output \u2018smartquote-a\u2019; Set-Content $HOME\\.ssh\\authorized_keys k", true},
		{"S4 backtick quote", "Write-Output `\"x; Set-Content $HOME\\.ssh\\authorized_keys k", true},
		{"S5 key read smart quote", "Get-Content ~\\.ssh\\id_ed25519; Write-Output \u2018smartquote-done\u2019", true},
		{"W06 apostrophe comment", "# set up the user's key\nSet-Content $HOME\\.ssh\\authorized_keys k", true},
		{"W06 CRLF apostrophe comment", "# set up the user's key\r\nSet-Content $HOME\\.ssh\\authorized_keys k", true},
		{"W06 literal tilde path", "# set up the user's key\nSet-Content ~\\.ssh\\authorized_keys k", true},
		{"W07 apostrophe comment Add-Content", "# set up the user's key\nAdd-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k", true},
		{"W03 U+2019 then apostrophe", "Write-Output \u2019a' ; Set-Content $HOME\\.ssh\\authorized_keys k", true},
		{"W03 no space", "Write-Output \u2019a'; Set-Content $HOME\\.ssh\\authorized_keys k", true},
		{"W08 backtick apostrophe", "Write-Output `' ; Set-Content $HOME\\.ssh\\authorized_keys k; Write-Output `'", true},
		{"W11 key read U+2019", "Get-Content ~\\.ssh\\id_ed25519; Write-Output \u2019done'", true},
		{"live TUI unterminated apostrophe then write", "Write-Output a' ; Set-Content $HOME\\.ssh\\authorized_keys k", true},
		{"V7 key read unterminated", "Get-Content ~\\.ssh\\id_ed25519; Write-Output 'unterminated", true},
		{"GAP-2389 cmd redirect", `cmd.exe /c "echo marker>>%USERPROFILE%\.ssh\authorized_keys"`, true},
		{"GAP-2389 .NET append", `[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')`, true},
		{"GAP-2389 pwsh -Command .NET", `pwsh -Command "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"GAP-2389 cmd /c powershell .NET", `cmd /c powershell -NoProfile -Command "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"GAP-2389 plain Add-Content", `Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker`, true},
		{"GAP-1500 H1-lone-cr", "$x = @'\rbenign\r'@; Set-Content ~\\.ssh\\authorized_keys k\n'@", true},
		{"GAP-1500 H1c-lone-cr-ctl", "$x = @'\rbenign\r'@; Set-Content notes.txt k\n'@", false},
		{"GAP-1500 H2-u2019", "$x = @'\nbenign\n\u2019@; Set-Content ~\\.ssh\\authorized_keys k\n'@", true},
		{"GAP-1500 H2c-u2019-ctl", "$x = @'\nbenign\n\u2019@; Set-Content notes.txt k\n'@", false},
		{"GAP-1500 H3-crlf-u2018", "$x = @'\r\nbenign\r\n\u2018@; Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k\r\n'@", true},
		{"GAP-1500 W01", "Write-Output a` #; Set-Content ~\\.ssh\\authorized_keys k", true},
		{"GAP-1500 W02", "Write-Output a` #; Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k", true},
		{"GAP-1500 W03", "Write-Output a` #; echo k >> ~\\.ssh\\authorized_keys", true},
		{"GAP-1500 G02-lone-cr-before-hash", "echo a\r#x; cp k.pub ~/.ssh/authorized_keys", true},
		{"GAP-1500 W-ctl-ssh-dir", "# Check the user's SSH folder\nTest-Path ~\\.ssh", false},
		{"GAP-1500 W-ctl-proj-write", "Write-Output a` #; Set-Content notes.txt k", false},
		{"GAP-1500 S1-comment-then-write", "# update keys\nSet-Content $HOME\\.ssh\\authorized_keys k", true},
		{"GAP-1500 S2-addcontent-env", "Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k; Write-Output smartquote-a", true},
		{"GAP-1500 S3-smartquote-write", "Write-Output \u2018smartquote-a\u2019; Set-Content $HOME\\.ssh\\authorized_keys k", true},
		{"GAP-1500 S4-backtick-quote", "Write-Output `\"x; Set-Content $HOME\\.ssh\\authorized_keys k", true},
		{"GAP-1500 S5-key-read-smartquote", "Get-Content ~\\.ssh\\id_ed25519; Write-Output \u2018smartquote-done\u2019", true},
		{"GAP-1500 S-ctl-proj-comment", "# update notes\nSet-Content notes.txt k; Write-Output \u2018smartquote-a\u2019", false},
		{"GAP-1500 S-ctl-ssh-dir-list", "Get-ChildItem ~\\.ssh # list only", false},
		{"GAP-1500 L1-getcommand", "Get-Command apply_patch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source", false},
		{"GAP-1500 IEX-ctl", "@'\nGet-Date\n'@ | Invoke-Expression", false},
		{"GAP-1500 IEX-ctl-arg", "Invoke-Expression \"Write-Output hello\"", false},
		{"GAP-1500 BYP-R104-N-WIN-BODY-IEX", "@'\n*** Begin Patch\n*** Add File: notes.txt\n+Add-Content $HOME\\.ssh\\authorized_keys (Get-Content key.pub)\n*** End Patch\n'@ | Invoke-Expression", true},
		{"GAP-1500 W04", "Write-Output a` #; Get-Content ~\\.ssh\\id_ed25519", true},
		{"GAP-1500 W04c-ctl", "Write-Output a` #; Get-Content notes.txt", false},
		{"GAP-1500 G03x", "echo a\\ #; head -c 4096 ~/.ssh/id_ed25519", true},
		{"GAP-1500 G04x", "echo a\\ #; cat ~/.ssh/id_ed25519 | base64", true},
		{"GAP-1500 G05x", "echo \u201c ; head -c 4096 ~/.ssh/id_ed25519 ; echo \u201d", true},
		{"GAP-1500 EA-H1", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\r'@; Set-Content ~\\.ssh\\authorized_keys evil; @'\n*** End Patch\n'@", true},
		{"GAP-1500 EP-H1", "@'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\r'@; Set-Content ~\\.ssh\\authorized_keys evil; @'\n*** End Patch\n'@ | apply_patch", true},
		{"GAP-1500 EA-H1-ctl", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\r'@; Set-Content notes.txt evil; @'\n*** End Patch\n'@", false},
		{"GAP-1500 EP-H1-ctl", "@'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\r'@; Set-Content notes.txt evil; @'\n*** End Patch\n'@ | apply_patch", false},
		{"GAP-1500 EA-H2", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\u2019@; Set-Content ~\\.ssh\\authorized_keys evil; @'\n*** End Patch\n'@", true},
		{"GAP-1500 EP-H2", "@'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\u2019@; Set-Content ~\\.ssh\\authorized_keys evil; @'\n*** End Patch\n'@ | apply_patch", true},
		{"GAP-1500 EA-H2-ctl", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\u2019@; Set-Content notes.txt evil; @'\n*** End Patch\n'@", false},
		{"GAP-1500 EP-H2-ctl", "@'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\u2019@; Set-Content notes.txt evil; @'\n*** End Patch\n'@ | apply_patch", false},
		{"GAP-1500 EA-H3", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\u2018@; Set-Content ~\\.ssh\\authorized_keys evil; @'\n*** End Patch\n'@", true},
		{"GAP-1500 EA-H3-ctl", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\u2018@; Set-Content notes.txt evil; @'\n*** End Patch\n'@", false},
		{"GAP-1500 EA-H4", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\u201b@; Set-Content ~\\.ssh\\authorized_keys evil; @'\n*** End Patch\n'@", true},
		{"GAP-1500 EA-H4-ctl", "apply_patch @'\n*** Begin Patch\n*** Add File: notes.txt\n+x\n\u201b@; Set-Content notes.txt evil; @'\n*** End Patch\n'@", false},
		{"ctl comment then notes", "# update notes\nSet-Content notes.txt k; Write-Output \u2018smartquote-a\u2019", false},
		{"ctl ssh dir list", "Get-ChildItem ~\\.ssh # list only", false},
		{"ctl apostrophe comment notes", "# set up the user's key\nSet-Content notes.txt k", false},
		{"ctl U+2019 notes", "Write-Output \u2019a' ; Set-Content notes.txt k", false},
		{"ctl backtick apostrophe notes", "Write-Output `' ; Set-Content notes.txt k; Write-Output `'", false},
		{"ctl read notes U+2019", "Get-Content notes.txt; Write-Output \u2019done'", false},
		{"ctl single-quoted literal", "Write-Output '$HOME\\.ssh\\authorized_keys is the file'", false},
		{"ctl cmd redirect project", `cmd.exe /c "echo marker>>%USERPROFILE%\project\report.txt"`, false},
		{"ctl .NET append project", `[System.IO.File]::AppendAllText('C:/Users/Alice/project/report.txt','marker')`, false},
		{"GAP-1473 Write-Output quoted tilde path", `Write-Output '~/.ssh/authorized_keys'`, false},
		{"GAP-1473 git commit message tilde path", `git commit -m 'Document ~/.ssh/authorized_keys'`, false},
		{"ctl git status", `git status`, false},
		{"ctl Get-ChildItem src", `Get-ChildItem .\src -Recurse -Filter *.go`, false},
	}
	for _, tool := range []string{"Bash", "PowerShell", "shell", "shell_command", "exec_command"} {
		for _, tc := range rows {
			t.Run(tool+"/"+tc.name, func(t *testing.T) {
				args, err := json.Marshal(map[string]string{"command": tc.command})
				if err != nil {
					t.Fatal(err)
				}
				input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
				input.DialectHint = agentHookWindowsShellDialect(input)
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connector,
					EnforcementCapable: true, windowsShellDialect: true,
				})
				got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
				if got != tc.block {
					t.Errorf("blocked=%t, want %t; hint=%q findings=%v", got, tc.block, input.DialectHint, findingIDs(findings))
				}
			})
		}
	}
}
