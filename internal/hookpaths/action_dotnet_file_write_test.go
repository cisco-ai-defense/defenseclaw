// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestActionWindowsDotNetFileWritesRequireResolvedDestination(t *testing.T) {
	const home = `C:\Users\Alice`
	const cwd = home + `\project`
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"GAP-0545 append literal", `[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')`, true},
		{"append environment home", `[IO.File]::AppendAllText("$env:USERPROFILE\.ssh\authorized_keys",'marker')`, true},
		{"write literal", `[System.IO.File]::WriteAllText('C:/Users/Alice/.ssh/authorized_keys','marker')`, true},
		{"one argument file creation", `[IO.File]::CreateText('C:/Users/Alice/.ssh/authorized_keys')`, true},
		{"append after ordinary command", `Write-Output ok; [System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')`, true},
		{"nested PowerShell append", `pwsh -Command "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"nested Windows PowerShell append", `powershell.exe -NoProfile -Command "[IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"CMD wraps PowerShell append", `cmd /c powershell -NoProfile -Command "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"CMD flags wrap PowerShell append", `cmd /s /c powershell -NoProfile -Command "[IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"env wraps PowerShell append", `env pwsh -Command "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"env flags wrap PowerShell append", `env -i LC_ALL=C pwsh -Command "[IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"env split wraps PowerShell append", `env -S "pwsh -Command [IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"sudo wraps PowerShell append", `sudo -n pwsh -Command "[IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, true},
		{"ordinary destination", `[System.IO.File]::AppendAllText('report.txt','marker')`, false},
		{"protected path as data", `[System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')`, false},
		{"quoted method text", `Write-Output "[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')"`, false},
		{"here-string method text", "$text = @'\n[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker')\n'@\nWrite-Output $text", false},
		{"read method", `[System.IO.File]::ReadAllText('C:/Users/Alice/.ssh/authorized_keys')`, false},
		{"nested PowerShell protected path as data", `pwsh -Command "[System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')"`, false},
		{"CMD wrapped protected path as data", `cmd /c powershell -NoProfile -Command "[System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')"`, false},
		{"env wrapped protected path as data", `env pwsh -Command "[System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')"`, false},
		{"env split protected path as data", `env -S "pwsh -Command [System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')"`, false},
		{"sudo wrapped protected path as data", `sudo -n pwsh -Command "[System.IO.File]::WriteAllText('report.txt','C:/Users/Alice/.ssh/authorized_keys')"`, false},
		{"incomplete call", `[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys','marker'`, false},
		{"missing content argument", `[System.IO.File]::AppendAllText('C:/Users/Alice/.ssh/authorized_keys')`, false},
		{"single quoted environment is literal", `[System.IO.File]::AppendAllText('$env:USERPROFILE\.ssh\authorized_keys','marker')`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ActionCommandDecision(tc.command, cwd, home) != ""
			if got != tc.block {
				t.Fatalf("denied=%v, audit=%q, want %v for %q", got, ActionCommandAuditReason(tc.command, cwd, home), tc.block, tc.command)
			}
		})
	}
}
