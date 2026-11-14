// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

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
