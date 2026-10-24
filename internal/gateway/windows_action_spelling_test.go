// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestR104ActionClassWindowsProtectedSpellings(t *testing.T) {
	const connector = "r104-class-windows"
	installToolCallCorpusProfileConnector(t, connector, "default")
	home := `C:\Users\Alice`
	encodePowerShell := func(body string) string {
		units := utf16.Encode([]rune(body))
		bytes := make([]byte, len(units)*2)
		for i, unit := range units {
			bytes[2*i], bytes[2*i+1] = byte(unit), byte(unit>>8)
		}
		return base64.StdEncoding.EncodeToString(bytes)
	}
	for _, tc := range []struct {
		name, command string
		dialect       actionfacts.Dialect
		block         bool
	}{
		{"GAP-0663 MSYS drive", `echo marker >> /c/Users/Alice/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"MSYS cp protected destination", `cp report.pub /c/Users/Alice/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"POSIX cp target-directory protected", `cp -t /c/Users/Alice/.ssh/authorized_keys report.pub`, actionfacts.DialectPOSIX, true},
		{"POSIX mv protected destination", `mv report.pub ~/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"POSIX ln protected destination", `ln -sf /c/Users/Alice/project/a.pub ~/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"POSIX rsync protected destination", `rsync report.pub ~/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"POSIX install protected destination", `install report.pub ~/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"POSIX sed protected destination", `sed -i s/a/b/ ~/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"POSIX dd protected destination", `dd if=report.pub of=C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPOSIX, true},
		{"CMD xcopy protected destination", `xcopy report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectCMD, true},
		{"CMD robocopy protected destination", `robocopy . C:\Users\Alice\.ssh\authorized_keys report.pub`, actionfacts.DialectCMD, true},
		{"PowerShell cpi protected destination", `cpi report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell mi protected destination", `mi report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell ni protected destination", `ni C:\Users\Alice\.ssh\authorized_keys -ItemType File`, actionfacts.DialectPowerShell, true},
		{"PowerShell sc protected destination", `sc C:\Users\Alice\.ssh\authorized_keys marker`, actionfacts.DialectPowerShell, true},
		{"PowerShell ac protected destination", `ac C:\Users\Alice\.ssh\authorized_keys marker`, actionfacts.DialectPowerShell, true},
		{"PowerShell ri protected destination", `ri C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell rni protected destination", `rni report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell iwr protected output", `iwr https://example.com/a.pub -OutFile C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell Invoke-WebRequest protected output", `Invoke-WebRequest https://example.com/a.pub -OutFile $env:USERPROFILE\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"ssh-keygen protected file", `ssh-keygen -f C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPOSIX, true},
		{"icacls protected file", `icacls C:\Users\Alice\.ssh\authorized_keys /grant Everyone:F`, actionfacts.DialectCMD, true},
		{"Copy-Item Verbose protected destination", `Copy-Item -Verbose report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"Copy-Item Container protected destination", `Copy-Item -Container report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"Copy-Item WhatIf protected destination", `Copy-Item -WhatIf report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"Copy-Item Filter protected destination", `Copy-Item -Filter *.pub report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"Copy-Item Exclude protected destination", `Copy-Item -Exclude *.tmp report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"Copy-Item unknown switch protected destination", `Copy-Item -FutureSwitch report.pub C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"timeout cp protected destination", `timeout 5 cp report.pub ~/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"nice numeric option protected child", `nice -10 cmd /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"sudo combined nE protected child", `sudo -nE cmd /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"sudo combined Ei protected child", `sudo -Ei cmd /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"ionice attached class protected child", `ionice -c2 cmd /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"env attached split protected child", `env --split-string="cmd /c echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"sudo unknown option protected child", `sudo --future-option cmd /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"env unknown option protected child", `env --future-option cmd /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"Copy-Item Verbose protected source", `Copy-Item -Verbose C:\Users\Alice\.ssh\authorized_keys report.pub`, actionfacts.DialectPowerShell, false},
		{"POSIX cp protected source", `cp /c/Users/Alice/.ssh/authorized_keys report.pub`, actionfacts.DialectPOSIX, false},
		{"POSIX cp target-directory protected source", `cp -t report.pub /c/Users/Alice/.ssh/authorized_keys`, actionfacts.DialectPOSIX, false},
		{"POSIX ln protected source", `ln -sf /c/Users/Alice/.ssh/authorized_keys report.pub`, actionfacts.DialectPOSIX, false},
		{"POSIX rsync protected source", `rsync -av /c/Users/Alice/.ssh/authorized_keys report.pub`, actionfacts.DialectPOSIX, false},
		{"POSIX dd protected input", `dd if=C:\Users\Alice\.ssh\authorized_keys of=report.pub`, actionfacts.DialectPOSIX, false},
		{"POSIX sed read only", `sed s/a/b/ ~/.ssh/authorized_keys`, actionfacts.DialectPOSIX, false},
		{"PowerShell Test-Path protected path", `Test-Path C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, false},
		{"PowerShell iwr protected data", `iwr https://example.com/a.pub -Body C:\Users\Alice\.ssh\authorized_keys -OutFile report.pub`, actionfacts.DialectPowerShell, false},
		{"Get-ChildItem protected path", `Get-ChildItem C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, false},
		{"Get-Content public key path", `Get-Content C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, false},
		{"GAP-0663 Cygwin drive", `echo marker >> /cygdrive/c/Users/Alice/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"MSYS mixed case", `echo marker >> /C/users/ALICE/.SSH/AUTHORIZED_KEYS`, actionfacts.DialectPOSIX, true},
		{"GAP-0545 CMD profile", `echo marker >> %USERPROFILE%\.ssh\authorized_keys`, actionfacts.DialectCMD, true},
		{"GAP-0575 PowerShell profile", `Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker`, actionfacts.DialectPowerShell, true},
		{"PowerShell path array literal", `Add-Content -Value marker -Path report.txt, C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell literal path array", `Add-Content -Value marker -LiteralPath report.txt, C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell abbreviated value literal", `Add-Content -Va marker C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell path array profile", `Add-Content -Value marker -Path report.txt, $env:USERPROFILE\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell abbreviated value profile", `Add-Content -Va marker $env:USERPROFILE\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell set abbreviated value destination", `Set-Content -Val marker C:\Users\Alice\.ssh\authorized_keys`, actionfacts.DialectPowerShell, true},
		{"PowerShell abbreviated value as data", `Add-Content -Va C:\Users\Alice\.ssh\authorized_keys report.txt`, actionfacts.DialectPowerShell, false},
		{"PowerShell set abbreviated value as data", `Set-Content -Val C:\Users\Alice\.ssh\authorized_keys report.txt`, actionfacts.DialectPowerShell, false},
		{"PowerShell abbreviated input as data", `Out-File -Inp C:\Users\Alice\.ssh\authorized_keys -FilePath report.txt`, actionfacts.DialectPowerShell, false},
		{"GAP-0545 .NET append literal", `[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')`, actionfacts.DialectPowerShell, true},
		{"GAP-0545 .NET nested PowerShell", `pwsh -Command "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, actionfacts.DialectPowerShell, true},
		{"GAP-0545 .NET CMD wrapper", `cmd /c powershell -NoProfile -Command "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, actionfacts.DialectCMD, true},
		{"GAP-0545 .NET env wrapper", `env pwsh -Command "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, actionfacts.DialectPOSIX, true},
		{"GAP-0545 .NET env split wrapper", `env -S "pwsh -Command [IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, actionfacts.DialectPOSIX, true},
		{"GAP-0545 .NET ordinary destination", `[System.IO.File]::AppendAllText('report.txt','marker')`, actionfacts.DialectPowerShell, false},
		{"GAP-0545 .NET protected read", `[System.IO.File]::ReadAllText('C:/Users/Alice/.ssh/authorized_keys')`, actionfacts.DialectPowerShell, false},
		{"GAP-0545 .NET incomplete write", `[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys')`, actionfacts.DialectPowerShell, false},
		{"GAP-0545 .NET protected path as data", `[System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')`, actionfacts.DialectPowerShell, false},
		{"GAP-0545 .NET CMD wrapper path as data", `cmd /c powershell -NoProfile -Command "[System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')"`, actionfacts.DialectCMD, false},
		{"GAP-0545 .NET env wrapper path as data", `env pwsh -Command "[System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')"`, actionfacts.DialectPOSIX, false},
		{"GAP-0545 .NET env split path as data", `env -S "pwsh -Command [IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')"`, actionfacts.DialectPOSIX, false},
		{"GAP-0545 extended drive", `echo marker >> //?/C:/Users/Alice/.ssh/authorized_keys`, actionfacts.DialectPOSIX, true},
		{"drive relative", `echo marker >> C:Users\Alice\.ssh\authorized_keys`, actionfacts.DialectCMD, false},
		{"PowerShell nested command", `pwsh -Command 'Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker'`, actionfacts.DialectPowerShell, true},
		{"PowerShell encoded command", `pwsh -EncodedCommand ` + encodePowerShell(`Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker`), actionfacts.DialectPowerShell, true},
		{"CMD nested command", `cmd /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"Windows env split wrapper", `env -S "cmd /c echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"Windows nice wrapper", `nice -n 5 cmd /c "echo marker >> %USERPROFILE%\.ssh\authorized_keys"`, actionfacts.DialectCMD, true},
		{"Cygwin private key read", `cat /cygdrive/c/Users/Alice/.ssh/id_ed25519`, actionfacts.DialectPOSIX, true},
		{"GAP-0789 PowerShell private read first", `Get-Content "$env:USERPROFILE\.ssh\id_ed25519"; Write-Output done`, actionfacts.DialectPowerShell, true},
		{"GAP-0789 PowerShell private read last", `Write-Output done; Get-Content "$env:USERPROFILE\.ssh\id_ed25519"`, actionfacts.DialectPowerShell, true},
		{"GAP-0789 CMD private read first", `type %USERPROFILE%\.ssh\id_ed25519 & echo done`, actionfacts.DialectCMD, true},
		{"Windows public key read", `Get-Content $HOME\.ssh\authorized_keys`, actionfacts.DialectPowerShell, false},
		{"CMD public key read", `type %USERPROFILE%\.ssh\authorized_keys`, actionfacts.DialectCMD, false},
		{"ordinary archive glob", `Compress-Archive -Path .\docs\* -DestinationPath .\out\docs.zip`, actionfacts.DialectPowerShell, false},
		{"ordinary fd duplication", `Get-ChildItem .\src 2>&1 > .\logs\list.log`, actionfacts.DialectPowerShell, false},
		{"ordinary assigned target", `$dst = ".\out\variable.txt"; Set-Content $dst ready`, actionfacts.DialectPowerShell, false},
		{"Join-Path positional protected target", `$dir = Join-Path $HOME '.ssh'; $dst = Join-Path $dir 'authorized_keys'; Add-Content -Value marker $dst`, actionfacts.DialectPowerShell, true},
		{"Join-Path positional data", `$dir = Join-Path $HOME '.ssh'; $dst = Join-Path $dir 'authorized_keys'; Add-Content -Value $dst report.txt`, actionfacts.DialectPowerShell, false},
		{"MSYS ordinary", `echo marker >> /c/Users/Alice/project/report.txt`, actionfacts.DialectPOSIX, false},
		{"CMD ordinary", `echo marker >> %USERPROFILE%\project\report.txt`, actionfacts.DialectCMD, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: "Bash", Args: args, CWD: home + `\project`, ActiveHome: home, DialectHint: tc.dialect}
			if tc.dialect != actionfacts.DialectCMD {
				input.DialectHint = agentHookWindowsShellDialect(input)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true})
			got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
			if got != tc.block {
				t.Fatalf("blocked=%t, want %t; findings=%v", got, tc.block, findingIDs(findings))
			}
		})
	}
}
