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
// twin. printf -v assigns a variable and is not a print, and a piped printf
// may feed a shell: its quoted words stay patterns. Redirect targets and
// unquoted words still count.
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
		{"printf 'x' | tee .ssh/authorized_k*", true},
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
	// A piped printf may feed a shell that expands the printed text: its
	// quoted pattern stays a pattern.
	for _, command := range []string{"printf 'cp a.txt .ssh/authorized_k*' | sh", "printf '.ssh/authorized_k*' | xargs -I{} cp a.txt {}"} {
		for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX} {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "protected-target" {
				t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
			}
		}
	}
	for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell} {
		if actionWindowsTextStatement([]string{"printf", "-v", "f", "*"}) {
			t.Errorf("dialect %q: printf -v is an assignment, not a print", dialect)
		}
	}
}
