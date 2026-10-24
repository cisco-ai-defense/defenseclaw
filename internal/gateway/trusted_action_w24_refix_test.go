// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestTrustedActionW24Continuation(t *testing.T) {
	const connector = "w24-continuation-test"
	installDefaultProfileConnector(t, connector)
	check := func(command, cwd, home string, dialect actionfacts.Dialect) []RuleFinding {
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{Tool: "shell", Command: command, CWD: cwd,
				ActiveHome: home, DialectHint: dialect},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
	}
	for _, tt := range []struct {
		name, command, cwd, home, rule string
		dialect                        actionfacts.Dialect
		block                          bool
	}{
		{"PowerShell continued benign pipeline", "Get-ChildItem |\n  Select-Object Name", `C:\repo`, `C:\Users\alice`, "", actionfacts.DialectPowerShell, false},
		{"PowerShell continued destructive pipeline", "Get-ChildItem |\n Remove-Item -Recurse -Force C:\\", `C:\repo`, `C:\Users\alice`, "CMD-RM-RF", actionfacts.DialectPowerShell, true},
		{"PowerShell continued statement", "Write-Output a;\n  Write-Output b", `C:\repo`, `C:\Users\alice`, "", actionfacts.DialectPowerShell, false},
		{"PowerShell standalone expression", "Write-Output (Get-Date)", `C:\repo`, `C:\Users\alice`, "", actionfacts.DialectPowerShell, false},
		{"PowerShell empty block", `& { }`, `C:\repo`, `C:\Users\alice`, "", actionfacts.DialectPowerShell, false},
		{"multiline bash script", "bash -c 'echo a\necho b'", "/repo", "/home/alice", "", actionfacts.DialectPOSIX, false},
		{"multiline sh script", "sh -c 'echo a\necho b'", "/repo", "/home/alice", "", actionfacts.DialectPOSIX, false},
		{"multiline bash destructive script", "bash -c 'echo a\nrm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"multiline sh destructive script", "sh -c 'echo a\nrm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"trap script calls function", "f() { rm -rf /; }; trap 'true; f' EXIT", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"trap option calls function", "f() { rm -rf /; }; trap -- f EXIT", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"trap direct destructive script", "trap 'true; rm -rf /' EXIT", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"trap dynamic action", "trap \"$action\" EXIT; true", "/repo", "/home/alice", "", actionfacts.DialectPOSIX, false},
		{"trap preview", "f() { rm -rf /; }; trap -p", "/repo", "/home/alice", "", actionfacts.DialectPOSIX, false},
		{"exported function in child shell", "f() { rm -rf /; }; export -f f; bash -c f", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"exported function through alternate spelling", "f() { rm -rf /; }; export -f -- f; sh -c f", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"second exported function", "f() { echo okay; }; g() { rm -rf /; }; export -f f g; bash -c g", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"unexported function", "f() { rm -rf /; }; export -fn f", "/repo", "/home/alice", "", actionfacts.DialectPOSIX, false},
		{"env nested list", "env sh -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"sudo nested list", "sudo sh -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"nohup nested list", "nohup sh -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"timeout nested list", "timeout 5 sh -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"dash nested list", "dash -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"bash option nested list", "bash -o pipefail -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"bash plus option nested list", "bash +o pipefail -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		// An unknown option is uncertainty, not persistence (W24 loop round 2).
		{"bash unsupported option", "bash -Z -c 'echo okay'", "/repo", "/home/alice", "", actionfacts.DialectPOSIX, false},
		{"bash unsupported option naming the protected file", "bash -Z -c 'echo okay' ~/.ssh/authorized_keys", "/repo", "/home/alice", "persistence.ssh_authorized_keys_command", actionfacts.DialectPOSIX, true},
		{"bash login option", "bash -lc 'echo okay'", "/repo", "/home/alice", "", actionfacts.DialectPOSIX, false},
		{"command wrapped nested list", "command sh -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"exec wrapped nested list", "exec sh -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"ksh nested list", "ksh -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"ash nested list", "ash -c 'true && rm -rf /'", "/repo", "/home/alice", "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"builtin cd", "builtin cd /home/alice && cat .ssh/id_rsa", "/repo", "/home/alice", "PATH-SSH-KEY", actionfacts.DialectPOSIX, true},
		{"command cd", "command cd /home/alice && cat .ssh/id_rsa", "/repo", "/home/alice", "PATH-SSH-KEY", actionfacts.DialectPOSIX, true},
		{"unmodeled directory change", "source ./env.sh; cat .ssh/id_rsa", "/repo", "/home/alice", "persistence.ssh_authorized_keys_command", actionfacts.DialectPOSIX, true},
		{"PowerShell Set-Location", `Set-Location C:\Users\alice; Get-Content .ssh\id_rsa`, `C:\repo`, `C:\Users\alice`, "PATH-SSH-KEY", actionfacts.DialectPowerShell, true},
		{"PowerShell push location", `Push-Location C:\Users\alice; Get-Content .ssh\id_rsa`, `C:\repo`, `C:\Users\alice`, "PATH-SSH-KEY", actionfacts.DialectPowerShell, true},
		{"PowerShell unknown location", `Set-Location $target; Get-Content .ssh\id_rsa`, `C:\repo`, `C:\Users\alice`, "persistence.ssh_authorized_keys_command", actionfacts.DialectPowerShell, true},
		{"cmd cd drive", `cd /d C:\Users\alice & type .ssh\id_rsa`, `C:\repo`, `C:\Users\alice`, "PATH-SSH-KEY", actionfacts.DialectCMD, true},
		{"cmd push location", `pushd C:\Users\alice & type .ssh\id_rsa`, `C:\repo`, `C:\Users\alice`, "PATH-SSH-KEY", actionfacts.DialectCMD, true},
		{"cmd drive without switch", `cd D:\ordinary & type .ssh\id_rsa`, `C:\Users\alice`, `C:\Users\alice`, "persistence.ssh_authorized_keys_command", actionfacts.DialectCMD, true},
		{"cmd grouped conditional", `if exist x (echo a & rmdir /s /q C:\)`, `C:\repo`, `C:\Users\alice`, "CMD-RM-RF", actionfacts.DialectCMD, true},
		{"cmd dynamic conditional header", `if exist %TARGET% (echo a & rmdir /s /q C:\)`, `C:\repo`, `C:\Users\alice`, "persistence.ssh_authorized_keys_command", actionfacts.DialectCMD, true},
		{"cmd parenthesized group", `(echo a & rmdir /s /q C:\)`, `C:\repo`, `C:\Users\alice`, "CMD-RM-RF", actionfacts.DialectCMD, true},
		{"PowerShell invoked block", `Write-Output a; & { Remove-Item -Recurse -Force C:\ }`, `C:\repo`, `C:\Users\alice`, "CMD-RM-RF", actionfacts.DialectPowerShell, true},
		{"PowerShell dot block", `. { Remove-Item -Recurse -Force C:\ }`, `C:\repo`, `C:\Users\alice`, "CMD-RM-RF", actionfacts.DialectPowerShell, true},
		{"PowerShell if block", `if ($true) { Write-Output a; Remove-Item -Recurse -Force C:\ }`, `C:\repo`, `C:\Users\alice`, "CMD-RM-RF", actionfacts.DialectPowerShell, true},
		{"PowerShell adjacent else block", `if ($true) { Write-Output a } else { Remove-Item -Recurse -Force C:\ }`, `C:\repo`, `C:\Users\alice`, "CMD-RM-RF", actionfacts.DialectPowerShell, true},
		{"PowerShell skipped directory change", `if ($false) { Set-Location C:\ordinary }; Get-Content .ssh\id_rsa`, `C:\Users\alice`, `C:\Users\alice`, "persistence.ssh_authorized_keys_command", actionfacts.DialectPowerShell, true},
		{"cmd conditional directory change", `if exist x (cd /d D:\ordinary) & type .ssh\id_rsa`, `C:\Users\alice`, `C:\Users\alice`, "persistence.ssh_authorized_keys_command", actionfacts.DialectCMD, true},
		{"PowerShell conditional path assignment", `if ($false) { $target = 'C:\ordinary' }; Get-Content $target`, `C:\Users\alice`, `C:\Users\alice`, "persistence.ssh_authorized_keys_command", actionfacts.DialectPowerShell, true},
		{"PowerShell foreach block", `foreach ($name in 'a','b') { Write-Output $name; Remove-Item -Recurse -Force C:\ }`, `C:\repo`, `C:\Users\alice`, "CMD-RM-RF", actionfacts.DialectPowerShell, true},
		{"PowerShell command in foreach header", `foreach ($name in Get-ChildItem C:\Users\alice\.ssh) { Write-Output $name }`, `C:\repo`, `C:\Users\alice`, "persistence.ssh_authorized_keys_command", actionfacts.DialectPowerShell, true},
		{"PowerShell unbalanced block", `Write-Output a; { Remove-Item -Recurse -Force C:\`, `C:\repo`, `C:\Users\alice`, "", actionfacts.DialectPowerShell, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			findings := check(tt.command, tt.cwd, tt.home, tt.dialect)
			blocked := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
			if blocked != tt.block {
				t.Errorf("blocked=%v, want %v: %v", blocked, tt.block, FindingStrings(findings))
			}
			if tt.rule != "" {
				finding := findingWithID(findings, tt.rule)
				if finding == nil || !finding.contributesToEnforcement() {
					t.Errorf("missing enforced %s: %v", tt.rule, FindingStrings(findings))
				}
			}
		})
	}
}
