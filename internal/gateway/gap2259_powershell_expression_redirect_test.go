// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP2259PowerShellExpressionRedirectUnknownFolder pins
// rel-1-0-10:GAP-2259: an expression statement redirected onto a file
// ("k" >> f, ("k") > f) writes f like echo k >> f does, so after a move to a
// folder the gateway cannot know ($env:X) a file of the unresolved-folder
// name lists gets the GAP-1556 unknown tier. config.yaml (the documented
// limit), a project file and a known folder stay unraised.
func TestGAP2259PowerShellExpressionRedirectUnknownFolder(t *testing.T) {
	for _, test := range []struct {
		name, command string
		want          bool
	}{
		{"append", `Set-Location $env:X; "k" >> authorized_keys`, true},
		{"write", `Set-Location $env:X; "k" > authorized_keys`, true},
		{"in .ssh", `Set-Location $env:X; "k" >> .ssh\authorized_keys`, true},
		{"parenthesized", `Set-Location $env:X; ("k") >> authorized_keys`, true},
		{"single quoted, private key", `Set-Location $env:X; ` + "k" + ` > id_ed25519`, true},
		{"variable", `Set-Location $env:X; $k >> authorized_keys`, true},
		{"inside pwsh -Command", `pwsh -NoProfile -Command "Set-Location $env:X; 1 >> authorized_keys"`, true},
		{"control: echo", `Set-Location $env:X; echo k >> authorized_keys`, true},
		{"limit: config.yaml", `Set-Location $env:X; "k" > config.yaml`, false},
		{"project file", `Set-Location $env:X; "k" > notes.txt`, false},
		{"known folder", `"k" >> authorized_keys`, false},
		{"absolute path", `Set-Location $env:X; "k" >> C:\temp\authorized_keys`, false},
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
