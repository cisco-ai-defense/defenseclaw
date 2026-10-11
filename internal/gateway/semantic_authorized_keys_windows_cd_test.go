// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestWindowsAuthorizedKeysLocationChains(t *testing.T) {
	const connector = "windows-authorized-keys-location"
	installToolCallCorpusProfileConnector(t, connector, "default")
	tests := []struct {
		name, tool, command, cwd, home string
		dialect                        actionfacts.Dialect
		block                          bool
	}{
		{"per-user quoted cd", "Bash", `"cd" ~/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"per-user cd", "Bash", `cd ~/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"per-user absolute", "Bash", `cd C:/Users/dcw-rv24p/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"per-user relative", "Bash", `cd .ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"per-user original", "Bash", `cd ~ && echo dccert-block-marker >> .ssh/authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"per-user control", "Bash", `cd ~ && echo ok >> rv24-notes.txt`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, false},
		{"managed quoted cd", "Bash", `"cd" ~/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24m`, `C:\Users\dcw-rv24m`, actionfacts.DialectPOSIX, true},
		{"managed cd", "Bash", `cd ~/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24m`, `C:\Users\dcw-rv24m`, actionfacts.DialectPOSIX, true},
		{"managed absolute", "Bash", `cd C:/Users/dcw-rv24m/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24m`, `C:\Users\dcw-rv24m`, actionfacts.DialectPOSIX, true},
		{"managed relative", "Bash", `cd .ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24m`, `C:\Users\dcw-rv24m`, actionfacts.DialectPOSIX, true},
		{"managed control", "Bash", `cd ~ && echo ok >> rv24-notes.txt`, `C:\Users\dcw-rv24m`, `C:\Users\dcw-rv24m`, actionfacts.DialectPOSIX, false},
		{"git bash home variable", "Bash", `cd $HOME/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"git bash pushd", "Bash", `pushd ~/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"git bash popd", "Bash", `pushd build; popd; cd .ssh; echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"git bash build control", "Bash", `cd build && echo ok >> notes.txt`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, false},
		{"git bash drive case", "Bash", `cd c:/USERS/DCW-RV24P/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"git bash drive mount", "Bash", `cd /c/Users/dcw-rv24p/.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPOSIX, true},
		{"git bash UNC", "Bash", `cd //server/share/Users/Alice/.ssh && echo dccert-block-marker >> authorized_keys`, `\\server\share\Users\Alice`, `\\server\share\Users\Alice`, actionfacts.DialectPOSIX, true},
		{"powershell path switch", "Bash", `Set-Location -Path $HOME\.ssh; Set-Content -Path authorized_keys -Value dccert-block-marker`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell literal path", "Bash", `cd -LiteralPath $env:USERPROFILE\.ssh; Add-Content -LiteralPath authorized_keys -Value dccert-block-marker`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell push location", "Bash", `Push-Location ~\.ssh; Out-File -Append -FilePath authorized_keys -InputObject dccert-block-marker`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell pop location", "Bash", `Push-Location build; Pop-Location; Set-Location .ssh; Add-Content authorized_keys dccert-block-marker`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell pop control", "Bash", `Push-Location .ssh; Pop-Location; Add-Content notes.txt ok`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, false},
		{"cmd drive switch", "Bash", `cd /d %USERPROFILE%\.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectCMD, true},
		{"cmd wrapped drive switch", "Bash", `cmd /d /c "cd /d %USERPROFILE%\.ssh && echo dccert-block-marker >> authorized_keys"`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, "", true},
		{"cmd wrapped control", "Bash", `cmd /d /c "cd build && echo ok >> notes.txt"`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, "", false},
		{"cmd home drive", "Bash", `pushd %HOMEDRIVE%%HOMEPATH%\.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectCMD, true},
		{"codex powershell", "Bash", `Set-Location ~\.ssh; Add-Content authorized_keys dccert-block-marker`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": test.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: test.tool, Args: args, CWD: test.cwd, ActiveHome: test.home, DialectHint: test.dialect}
			if test.dialect != actionfacts.DialectCMD {
				input.DialectHint = agentHookWindowsShellDialect(input)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true,
			})
			want := guardrailActionAllow
			if test.block {
				want = guardrailActionBlock
			}
			if got := buildVerdict(findings, "tool_call").Action; got != want {
				t.Errorf("verdict %s, want %s; findings=%v", got, want, findingIDs(findings))
			}
			if test.block {
				if ids := findingIDs(findings); len(ids) != 1 || ids[0] != "persistence.ssh_authorized_keys_command" {
					t.Errorf("finding IDs = %v, want one authorized-keys command finding", ids)
				}
			} else if len(findings) != 0 {
				t.Errorf("benign command findings = %v", findingIDs(findings))
			}
		})
	}
}
