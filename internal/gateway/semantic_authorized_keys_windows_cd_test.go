// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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
		{"powershell location path array", "Bash", `Set-Location $HOME; Add-Content -Value marker -Path report.txt, .ssh\authorized_keys`, `C:\Users\dcw-rv24p\project`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell location abbreviated value", "Bash", `Set-Location $HOME; Add-Content -Va marker .ssh\authorized_keys`, `C:\Users\dcw-rv24p\project`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell location data control", "Bash", `Set-Location $HOME; Add-Content -Va .ssh\authorized_keys report.txt`, `C:\Users\dcw-rv24p\project`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell push location", "Bash", `Push-Location ~\.ssh; Out-File -Append -FilePath authorized_keys -InputObject dccert-block-marker`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell pop location", "Bash", `Push-Location build; Pop-Location; Set-Location .ssh; Add-Content authorized_keys dccert-block-marker`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell pop control", "Bash", `Push-Location .ssh; Pop-Location; Add-Content notes.txt ok`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, false},
		{"cmd drive switch", "Bash", `cd /d %USERPROFILE%\.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectCMD, true},
		{"cmd wrapped drive switch", "Bash", `cmd /d /c "cd /d %USERPROFILE%\.ssh && echo dccert-block-marker >> authorized_keys"`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, "", true},
		{"cmd wrapped control", "Bash", `cmd /d /c "cd build && echo ok >> notes.txt"`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, "", false},
		{"cmd home drive", "Bash", `pushd %HOMEDRIVE%%HOMEPATH%\.ssh && echo dccert-block-marker >> authorized_keys`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectCMD, true},
		{"codex powershell", "Bash", `Set-Location ~\.ssh; Add-Content authorized_keys dccert-block-marker`, `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell newline protected", "Bash", "Write-Output 'ok'\nAdd-Content -Path '~/.ssh/authorized_keys' -Value 'marker'", `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, true},
		{"powershell newline ordinary", "Bash", "Write-Output 'ok'\nAdd-Content -Path 'notes.txt' -Value 'marker'", `C:\Users\dcw-rv24p`, `C:\Users\dcw-rv24p`, actionfacts.DialectPowerShell, false},
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

func TestWindowsNativeLocationArrayBinder(t *testing.T) {
	input := actionfacts.Input{
		CWD: `C:\Users\Alice\project`, ActiveHome: `C:\Users\Alice`,
		DialectHint: actionfacts.DialectPowerShell,
	}
	for _, tc := range []struct {
		command string
		write   bool
	}{
		{`Set-Location $HOME; Add-Content -Value marker -Path report.txt, .ssh\authorized_keys`, true},
		{`Set-Location $HOME; Add-Content -Va marker .ssh\authorized_keys`, true},
		{`Set-Location $HOME; Add-Content -Va .ssh\authorized_keys report.txt`, false},
	} {
		input.Command = tc.command
		if got := trustedWindowsNativeLocationWrite(input, actionfacts.DialectPowerShell); got != tc.write {
			t.Errorf("native location write=%t, want %t: %s", got, tc.write, tc.command)
		}
	}
}

// The managed gateway runs as a different account. Its hook can report an
// unresolved operand inside the user's profile even though the shell can write
// there. Use native paths in every host OS to cover Git Bash's path spellings.
func TestWindowsManagedOrdinaryLocationWrites(t *testing.T) {
	const connector = "windows-managed-ordinary-location"
	installToolCallCorpusProfileConnector(t, connector, "default")
	type row struct {
		name, command, target string
		dialect               actionfacts.Dialect
		block                 bool
	}
	rows := []row{
		{"cd nested", `cd rv25/build && echo ok >> notes.txt`, `rv25/build/notes.txt`, actionfacts.DialectPOSIX, false},
		{"cd parent", `cd rv25 && echo ok3 >> notes3.txt`, `rv25/notes3.txt`, actionfacts.DialectPOSIX, false},
		{"cd drive", `cd C:/Users/USER/rv25/build && echo ok4 >> notes4.txt`, `rv25/build/notes4.txt`, actionfacts.DialectPOSIX, false},
		{"cd home", `cd ~/rv25/build && echo ok5 >> notes5.txt`, `rv25/build/notes5.txt`, actionfacts.DialectPOSIX, false},
		{"redirect nested", `echo ok6 >> rv25/build/notes6.txt`, `rv25/build/notes6.txt`, actionfacts.DialectPOSIX, false},
		{"truncate nested", `cd rv25/build && echo ok7 > notes7.txt`, `rv25/build/notes7.txt`, actionfacts.DialectPOSIX, false},
		{"redirect project", `echo ok8 >> proj1/n.txt`, `proj1/n.txt`, actionfacts.DialectPOSIX, false},
		{"redirect documents", `echo ok9 >> Documents/n9.txt`, `Documents/n9.txt`, actionfacts.DialectPOSIX, false},
		{"home control", `cd ~ && echo ok >> rv25-notes.txt`, `rv25-notes.txt`, actionfacts.DialectPOSIX, false},
		{"dot control", `echo ok10 >> ./n10.txt`, `n10.txt`, actionfacts.DialectPOSIX, false},
		{"original protected", `cd ~ && echo marker >> .ssh/authorized_keys`, `.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"quoted cd protected", `"cd" ~/.ssh && echo marker >> authorized_keys`, `.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"home cd protected", `cd ~/.ssh && echo marker >> authorized_keys`, `.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"drive cd protected", `cd C:/Users/USER/.ssh && echo marker >> authorized_keys`, `.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"relative cd protected", `cd .ssh && echo marker >> authorized_keys`, `.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"pushd protected", `pushd ~/.ssh && echo marker >> authorized_keys`, `.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"cmd protected", `cmd /d /c "cd /d %USERPROFILE%\.ssh && echo marker >> authorized_keys"`, `.ssh/authorized_keys`, "", true},
		{"codex add control", `Set-Location ~\rv25\build; Add-Content notes.txt ok`, `rv25/build/notes.txt`, actionfacts.DialectPowerShell, false},
		{"codex home control", `Add-Content ~\rv25-notes-cx.txt ok`, `rv25-notes-cx.txt`, actionfacts.DialectPowerShell, false},
		{"codex add protected", `Set-Location ~\.ssh; Add-Content authorized_keys marker`, `.ssh/authorized_keys`, actionfacts.DialectPowerShell, true},
		{"codex literal protected", `Set-Location -LiteralPath $env:USERPROFILE\.ssh; Set-Content -LiteralPath authorized_keys -Value marker`, `.ssh/authorized_keys`, actionfacts.DialectPowerShell, true},
		{"codex out-file protected", `Push-Location ~\.ssh; "marker" | Out-File -Append authorized_keys`, `.ssh/authorized_keys`, actionfacts.DialectPowerShell, true},
		{"case protected", `cd ~/.SSH && echo marker >> AUTHORIZED_KEYS2`, `.ssh/authorized_keys2`, actionfacts.DialectPOSIX, true},
	}
	for _, target := range []string{
		`C:\Users\dcw-rv25m\.SSH.\notes.txt`,
		`C:\Users\dcw-rv25m\rv25\AUTHORIZED_KEYS.`,
		`C:\Users\dcw-rv25m\rv25\authorized_keys:stream`,
		`C:\Users\dcw-rv25m\RV25~1\notes.txt`,
		`C:\Users\dcw-rv25m\rv25\..\notes.txt`,
	} {
		if windowsLocationOrdinaryWriteTarget(target) {
			t.Errorf("ambiguous Windows target %q was treated as ordinary", target)
		}
	}
	for _, managed := range []bool{false, true} {
		user := "dcw-rv25p"
		if managed {
			user = "dcw-rv25m"
		}
		home := `C:\Users\` + user
		for _, row := range rows {
			t.Run(user+"/"+row.name, func(t *testing.T) {
				command := strings.ReplaceAll(row.command, "C:/Users/USER/", "C:/Users/"+user+"/")
				args, err := json.Marshal(map[string]string{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				input := actionfacts.Input{Tool: "Bash", Args: args, CWD: home, ActiveHome: home, DialectHint: row.dialect}
				if row.dialect != actionfacts.DialectCMD {
					input.DialectHint = agentHookWindowsShellDialect(input)
				}
				target := filepath.Join(home, filepath.FromSlash(row.target))
				if !row.block && !windowsLocationOrdinaryWriteTarget(target) {
					t.Fatalf("ordinary target %q was not recognized", target)
				}
				if row.block && windowsLocationOrdinaryWriteTarget(target) {
					t.Fatalf("protected target %q was treated as ordinary", target)
				}
				request := trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connector,
					EnforcementCapable: true, ProtectedHomeHook: managed,
				}
				if managed {
					request.ResolvedWriteTargets = map[string]string{
						hookpaths.CWDKey:                     home,
						hookpaths.DirectoryFactPrefix + home: home,
						target:                               "",
					}
				}
				findings := dispatchTrustedAction(t.Context(), request)
				want := guardrailActionAllow
				if row.block {
					want = guardrailActionBlock
				}
				if got := buildVerdict(findings, "tool_call").Action; got != want {
					t.Errorf("verdict %s, want %s; findings=%v", got, want, findingIDs(findings))
				}
				if row.block {
					if ids := findingIDs(findings); len(ids) != 1 || ids[0] != "persistence.ssh_authorized_keys_command" {
						t.Errorf("finding IDs = %v, want one authorized-keys finding", ids)
					}
				} else if len(findings) != 0 {
					t.Errorf("ordinary command findings = %v", findingIDs(findings))
				}
			})
		}
	}
}
