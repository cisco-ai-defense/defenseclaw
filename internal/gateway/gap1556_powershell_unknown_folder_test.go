// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP1556PowerShellUnknownFolderKeyNames pins rel-1-0-10:GAP-1556 (lead
// ruling 2026-11-26, option 2): a PowerShell write after a move to a folder
// the gateway cannot know ($env:X, pwsh -wd $env:X, either inside pwsh
// -Command) is the unknown tier only for a file of the unresolved-folder
// name lists, alone or in .ssh. config.yaml and every common project file
// stay unraised (the documented limit), so do a read, a known folder and a
// path that names its own folder.
func TestGAP1556PowerShellUnknownFolderKeyNames(t *testing.T) {
	for _, test := range []struct {
		name, command string
		want          bool
	}{
		{"Set-Location env, keys", `Set-Location $env:X; Set-Content -Path authorized_keys -Value x`, true},
		{"wd env, keys", `pwsh -NoProfile -wd $env:X -Command "Set-Content -Path authorized_keys -Value m"`, true},
		{"inside pwsh -Command, keys", `pwsh -NoProfile -Command "Set-Location $env:X; Set-Content -Path authorized_keys -Value m"`, true},
		{"keys2, append", `Set-Location $env:X; Add-Content -Path authorized_keys2 -Value x`, true},
		{"private key", `Set-Location $env:X; Set-Content -Path id_ed25519 -Value x`, true},
		{"git credentials", `Set-Location $env:X; Set-Content -Path .git-credentials -Value x`, true},
		{"key in .ssh", `Set-Location $env:X; Set-Content -Path .ssh\id_rsa -Value x`, true},
		{"upper case", `Set-Location $env:X; Set-Content -Path AUTHORIZED_KEYS -Value x`, true},
		{"remove", `Set-Location $env:X; Remove-Item authorized_keys`, true},
		{"limit: config.yaml", `Set-Location $env:X; Set-Content -Path config.yaml -Value m`, false},
		{"limit: wd env, config.yaml", `pwsh -NoProfile -wd $env:X -Command "Set-Content -Path config.yaml -Value m"`, false},
		{"settings.json", `Set-Location $env:X; Set-Content -Path settings.json -Value x`, false},
		{".env.example", `Set-Location $env:X; Set-Content -Path .env.example -Value x`, false},
		{"another file", `Set-Location $env:X; Set-Content -Path authorized_keys.bak -Value x`, false},
		{"read", `Set-Location $env:X; Get-Content authorized_keys`, false},
		{"known folder", `Set-Content -Path authorized_keys -Value x`, false},
		{"absolute path", `Set-Location $env:X; Set-Content -Path C:\temp\authorized_keys -Value x`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{
				Tool: "powershell", Command: test.command, CWD: `C:\Users\alice\project`,
				ActiveHome: `C:\Users\alice`, DialectHint: actionfacts.DialectPowerShell,
			}
			facts := actionfacts.Analyze(input)
			got := powerShellUnresolvedFolderNamesKeyFile(facts) ||
				powerShellHostReadingsNameKeyFile(trustedActionRequest{Input: input}, facts)
			if got != test.want {
				t.Fatalf("%q: unknown tier %v, want %v", test.command, got, test.want)
			}
		})
	}
}
