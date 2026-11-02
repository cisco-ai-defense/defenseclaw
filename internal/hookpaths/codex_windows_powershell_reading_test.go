// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestPowerShellPrintOfAnUnquotedPatternIsText is the Codex route of
// rel-1-0-6:GAP-0211 (sweep 7, dc-win2): Codex on Windows has its shell
// calls read as PowerShell, where the POSIX dot rule of f0f21b72f4 does not
// apply, and echo * at the home was denied (a plain echo gets no
// PowerShell hint there, so the plain readings count as well). PowerShell has no shell glob:
// a print gets its unquoted words as written. A piped print, a redirect, a
// writer and a spelled home path keep their verdicts.
func TestPowerShellPrintOfAnUnquotedPatternIsText(t *testing.T) {
	const home = `C:\Users\b00`
	for _, ps := range []actionfacts.Dialect{actionfacts.DialectPowerShell, ""} {
		for _, command := range []string{
			"echo *",
			"echo * && echo done",
			"echo *; echo done",
			"echo */",
			"Write-Output *",
			"Write-Output .ssh/authorized_k*",
		} {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, ps, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", ps, command, got)
			}
		}
		for _, command := range []string{
			"echo .ssh/authorized_k* | xargs -I{} cp a.txt {}",
			"echo .ssh/authorized_k* | ForEach-Object { Add-Content -Path $_ -Value k }",
			"echo * > .ssh/authorized_keys",
			"echo x; Copy-Item a.txt .ssh/authorized_k*",
			"Write-Output $HOME/.ssh/authorized_keys",
			"echo (Add-Content -Path .ssh/authorized_k* -Value k)",
		} {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, ps, nil); got != "protected-target" {
				t.Errorf("dialect %q %q = %q, want protected-target", ps, command, got)
			}
		}
	}
}

func TestWindowsDiscardRedirectKeepsAReadOnlyStatement(t *testing.T) {
	for _, row := range []struct {
		words []string
		want  bool
	}{
		{[]string{"uniq", "keylink", ">", "/dev/null"}, true},
		{[]string{"uniq", "keylink", "2>", "$null"}, true},
		{[]string{"cat", "keylink", ">", "NUL", "2>&1"}, true},
		{[]string{"uniq", "keylink", ">", "out.txt"}, false},
		{[]string{"uniq", "keylink", ">>", ".ssh/authorized_keys"}, false},
		{[]string{"cp", "a", "b", ">", "/dev/null"}, false},
	} {
		if got := actionKnownReadOnlyWindows(row.words); got != row.want {
			t.Errorf("%q read-only = %v, want %v", row.words, got, row.want)
		}
	}
}
