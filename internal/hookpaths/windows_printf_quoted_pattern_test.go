// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1717 (Codex PowerShell row): from the home folder of a Windows home,
// a quoted pattern that printf prints (a staged patch envelope with its ***
// lines, a lone '*') was read as a glob that selects .ssh, while the same
// echo was text. printf only prints, as echo does: its quoted words are
// text in every Windows reading, and each row gets the verdict of its echo
// twin. printf -v assigns a variable and is not a print. Redirect targets
// and unquoted words still count.
func TestWindowsPrintfQuotedPatternIsTextAsEcho(t *testing.T) {
	envelope := "*** Begin Patch\n*** Update File: notes.txt\n@@\n marker\n+x\n*** End Patch"
	const home = `C:\Users\b00`
	rows := []struct {
		command string
		block   bool
	}{
		{"printf '*'", false},
		{"printf '" + envelope + "'; cat benign.patch | apply_patch", false},
		{"printf '%s\\n' '*'; cp a.txt b.txt", false},
		{"printf '*.md'; git status", false},
		{"printf x > ~/.ssh/authorized_keys", true},
		{"printf x >> $HOME/.ssh/authorized_keys", true},
		{"printf '*'; cp a.txt .ssh/authorized_keys", true},
		{"printf x > .ssh/authorized_k*", true},
		{"printf '*' > .ssh/authorized_keys", true},
	}
	for _, row := range rows {
		twin := "echo" + strings.TrimPrefix(row.command, "printf")
		for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX} {
			got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, home, home, dialect, nil)
			if blocked := got == "protected-target"; blocked != row.block {
				t.Errorf("dialect %q %q = %q, want block=%v", dialect, row.command, got, row.block)
			}
			if echo := ActionCommandDecisionWithDialectAndGlobFacts(twin, home, home, dialect, nil); echo != got {
				t.Errorf("dialect %q %q = %q, its echo twin %q = %q", dialect, row.command, got, twin, echo)
			}
		}
	}
	for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell} {
		if actionWindowsTextStatement([]string{"printf", "-v", "f", "*"}) {
			t.Errorf("dialect %q: printf -v is an assignment, not a print", dialect)
		}
	}
}

// rel-1-0-6:GAP-0227: text that echo or printf prints into a shell (sh,
// bash, pwsh, cmd, Invoke-Expression) is a script there, so its quoted
// patterns are paths and keep their verdict; the GAP-1717 text reading
// applies only when the printed text is not run. Each printf row gets the
// verdict of its echo twin in every Windows reading. Benign scripts piped
// into a shell still allow.
func TestWindowsTextPipedIntoAShellKeepsItsPatterns(t *testing.T) {
	const home = `C:\Users\b00`
	rows := []struct {
		command string
		block   bool
	}{
		{"printf 'cp a.txt .ssh/authorized_k*' | bash", true},
		{"printf 'cat a.txt >> .ssh/authorized_k*' | sh", true},
		{"printf 'cp a.txt .ssh/authorized_k*' | grep cp | sh", true},
		{"printf 'cp a.txt .ssh/authorized_k*' | iex", true},
		{"printf 'cp a.txt .ssh/authorized_k*' | pwsh -NoProfile -Command -", true},
		{"printf 'echo hi' | sh", false},
		{"printf 'git status' | bash", false},
		{"printf 'ls' | sh", false},
		{"printf '*' | Out-Host", false},
		{"printf 'cp a.txt .ssh/authorized_k*' | Out-Host", false},
		{"printf 'cp a.txt .ssh/authorized_k*'; ls | sh", false},
	}
	for _, row := range rows {
		twin := "echo" + strings.TrimPrefix(row.command, "printf")
		for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX} {
			got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, home, home, dialect, nil)
			if blocked := got == "protected-target"; blocked != row.block {
				t.Errorf("dialect %q %q = %q, want block=%v", dialect, row.command, got, row.block)
			}
			if echo := ActionCommandDecisionWithDialectAndGlobFacts(twin, home, home, dialect, nil); echo != got {
				t.Errorf("dialect %q %q = %q, its echo twin %q = %q", dialect, row.command, got, twin, echo)
			}
		}
	}
}
