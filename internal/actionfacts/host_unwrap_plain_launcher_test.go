// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPlainHostLauncherLine (rel-1-0-10:GAP-0345): only a powershell or pwsh
// launcher of plain words is the same call in every shell.
func TestPlainHostLauncherLine(t *testing.T) {
	for text, want := range map[string]bool{
		"powershell -EncodedCommand RwBlAHQALQBEAGEAdABlAA==":    true,
		"  pwsh -NoProfile -enc RwBlAHQALQBEAGEAdABlAA==  ":      true,
		"powershell.exe -ep Bypass -EncodedCommand R2V0LURhdGU=": true,
		"powershell -Command Get-Date":                           true,
		"powershell":                                             false,
		"powershell -Command 'Get-Date'":                         false,
		"powershell -Command Get-Date; rm -rf x":                 false,
		"powershell -EncodedCommand $X":                          false,
		"powershell -EncodedCommand R2V0 | sh":                   false,
		`C:\tmp\powershell.exe -EncodedCommand R2V0LURhdGU=`:     false,
		"/tmp/powershell -EncodedCommand R2V0LURhdGU=":           false,
		"cmd /c powershell -EncodedCommand R2V0LURhdGU=":         false,
		"ls -la /tmp": false,
		"powershell -EncodedCommand R2V0LURhdGU= > /tmp/out.txt": false,
		"powershell -EncodedCommand R2V0LURhdGU= `\n& calc":      false,
	} {
		if got := plainHostLauncherLine(text); got != want {
			t.Errorf("plainHostLauncherLine(%q) = %v, want %v", text, got, want)
		}
	}
}

// TestTruncatedHostCall (rel-1-0-10:GAP-0345, GAP-0318): past the input bound
// a call is truncated when it holds a host script the script reading would
// have read; one long ordinary PowerShell statement is not.
func TestTruncatedHostCall(t *testing.T) {
	long := strings.Repeat("ordinary text line\n", 4000)
	for _, test := range []struct {
		name, tool string
		hint       Dialect
		command    string
		want       bool
	}{
		{"plain launcher line, POSIX tool", "Bash", "", "powershell -EncodedCommand " + strings.Repeat("QQBB", 20000), true},
		{"launcher in a PowerShell list", "PowerShell", "", "Write-Output a; powershell -EncodedCommand " + strings.Repeat("QQBB", 20000), true},
		{"call block, PowerShell hint", "Bash", DialectPowerShell, "& { Set-Content a.txt -Value '" + long + "' }", true},
		{"iex word", "pwsh", "", "$s = '" + long + "'; iex $s", true},
		{"one long PowerShell statement", "PowerShell", "", "Set-Content notes.txt -Value @'\n" + long + "'@", false},
		{"index is not iex", "PowerShell", "", "Set-Content index.txt -Value @'\n" + long + "'@", false},
		{"launcher word in a POSIX script", "Bash", "", "echo " + long + "; echo powershell", false},
	} {
		args, err := json.Marshal(map[string]string{"command": test.command})
		if err != nil {
			t.Fatal(err)
		}
		if got := TruncatedHostCall(Input{Tool: test.tool, Args: args, DialectHint: test.hint}); got != test.want {
			t.Errorf("%s: TruncatedHostCall = %v, want %v", test.name, got, test.want)
		}
	}
}
