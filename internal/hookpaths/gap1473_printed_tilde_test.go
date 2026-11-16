// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1473: Codex names its Windows PowerShell tool Bash, so the gateway can
// read Write-Output '~/.ssh/authorized_keys' with the POSIX grammar. Write-Output
// and Write-Host print their arguments as written (and no POSIX shell has
// them), so a quoted ~ there is text in every reading, while a cmdlet path
// parameter, a redirect or a writer keeps the protected-target decision.
func TestActionPrintedQuotedTildeIsTextInEveryReading(t *testing.T) {
	for _, home := range []string{`C:\Users\u`, "/home/u"} {
		if home[0] == '/' && runtime.GOOS == "windows" {
			// A Windows host has no POSIX home to read the rows against.
			continue
		}
		cwd := home + "/proj"
		if home[0] != '/' {
			cwd = home + `\proj`
		}
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX, actionfacts.DialectPowerShell} {
			for _, tc := range []struct{ name, command, want string }{
				{"Write-Output quoted tilde", `Write-Output '~/.ssh/authorized_keys'`, ""},
				{"Write-Host quoted tilde", `Write-Host "~/.ssh/authorized_keys"`, ""},
				{"echo quoted tilde", `echo '~/.ssh/authorized_keys'`, ""},
				{"git commit message", `git commit -m 'Document ~/.ssh/authorized_keys'`, ""},
				{"Write-Output redirected to the key", `Write-Output k > ~/.ssh/authorized_keys`, "protected-target"},
				{"Write-Output then a writer", `Write-Output '~/.ssh/authorized_keys'; cp k.pub ~/.ssh/authorized_keys`, "protected-target"},
				{"Set-Content quoted tilde", `Set-Content '~/.ssh/authorized_keys' k`, "protected-target"},
				{"unquoted tilde printed then appended", `Write-Output k >> ~/.ssh/authorized_keys`, "protected-target"},
			} {
				if hint == actionfacts.DialectPOSIX && tc.name == "Set-Content quoted tilde" {
					// A POSIX shell has no Set-Content; this row is the
					// PowerShell reading's (GAP-1473 cmdlet path parameter).
					continue
				}
				got := ActionCommandDecisionWithDialectAndGlobFacts(tc.command, cwd, home, hint, nil)
				if got != tc.want {
					t.Errorf("home=%s hint=%q %s: %q = %q, want %q", home, hint, tc.name, tc.command, got, tc.want)
				}
			}
		}
	}
}
