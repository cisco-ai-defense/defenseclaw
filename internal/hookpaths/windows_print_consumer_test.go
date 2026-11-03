// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestWindowsPrintFeedingAConsumerKeepsItsPatterns pins the rows the
// IN-bd-classifier review checked on d60f8a4147 (r107-bd-hookparse3 port of
// fix/r107-bd-classifier and fix/r107-bd-echo): a printf or echo whose
// output a later pipeline stage runs or turns into arguments (a shell,
// Invoke-Expression, ForEach-Object, xargs) keeps its quoted patterns in the
// Windows readings, and a printf first line no longer hides a writer on
// the next line (rel-1-0-6:GAP-0234 line ends, review must-fix rows).
func TestWindowsPrintFeedingAConsumerKeepsItsPatterns(t *testing.T) {
	const home = `C:\Users\b00`
	dialects := []actionfacts.Dialect{"", actionfacts.DialectPowerShell}
	piped := []string{
		"printf 'cp a.txt .ssh/authorized_k*' | sh",
		"printf 'cp a.txt .ssh/authorized_k*' | bash",
		"printf 'cp a.txt .ssh/authorized_k*' 2>&1 | sh",
		"printf 'cp a.txt .ssh/authorized_k*' | iex",
		"printf 'cp a.txt .ssh/authorized_k*' | Invoke-Expression",
		"printf '.ssh/authorized_k*' | % { cp a.txt $_ }",
		"printf '.ssh/authorized_k*' | ForEach-Object { Copy-Item a.txt $_ }",
		"printf '.ssh/authorized_k*' | xargs -I{} cp a.txt {}",
	}
	for _, command := range piped {
		for _, print := range []string{"printf", "echo"} {
			row := print + strings.TrimPrefix(command, "printf")
			for _, dialect := range dialects {
				if got := ActionCommandDecisionWithDialectAndGlobFacts(row, home, home, dialect, nil); got != "protected-target" {
					t.Errorf("dialect %q %q = %q, want protected-target", dialect, row, got)
				}
			}
		}
	}
	for _, eol := range []string{"\n", "\r\n"} {
		for _, writer := range gap0234SecondLineWriters {
			command := "printf 'x'" + eol + writer
			single := "printf 'x'; " + writer
			for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX} {
				// Git Bash alone reads a POSIX call with no Windows syntax
				// on a native host and passes a quoted pattern as written:
				// the line end then gives its one-line twin's verdict
				// (189c685291).
				want := "protected-target"
				if dialect == actionfacts.DialectPOSIX && GitBashReadsAlone(single, home) {
					want = ActionCommandDecisionWithDialectAndGlobFacts(single, home, home, dialect, nil)
				}
				if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != want {
					t.Errorf("dialect %q %q = %q, want %q", dialect, command, got, want)
				}
			}
		}
	}
	for _, command := range []string{"printf '*'", "printf '%s\\n' '*'", "echo 'git status' | bash", "printf 'ls' | sh", "printf '*' | Out-Host"} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", dialect, command, got)
			}
		}
	}
}

func TestGAP0227WindowsWrappedShellReaderStandalone(t *testing.T) {
	const home = `C:\Users\b00`
	for _, row := range []struct {
		command string
		want    string
	}{
		{"echo 'cp a.txt .ssh/authorized_k*' | env bash", "protected-target"},
		{"printf 'cp a.txt .ssh/authorized_k*' | env -C ~ sh", "protected-target"},
		{"echo 'cp a.txt .ssh/authorized_k*' | env -u X pwsh -Command -", "protected-target"},
		{"echo 'cp a.txt .ssh/authorized_k*' | env X=1 -- bash", "protected-target"},
		{"echo 'cp a.txt .ssh/authorized_k*' | env -- X=1 bash", "protected-target"},
		{"echo 'cp a.txt .ssh/authorized_k*' | env -S 'bash -s'", "protected-target"},
		{"echo 'cp a.txt .ssh/authorized_k*' | env --split-string='bash -s'", "protected-target"},
		{"echo 'cp a.txt .ssh/authorized_k*' | env --chdir=. bash", "protected-target"},
		{"echo 'git status' | env bash", ""},
		{"echo 'cp a.txt .ssh/authorized_k*' | env -S 'cat -n'", ""},
		{"echo 'cp a.txt .ssh/authorized_k*' | ./env -S 'cat -n'", "protected-target"},
		{"echo 'cp a.txt .ssh/authorized_k*' | env -S 'cat -n' | sh", "protected-target"},
	} {
		for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell} {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, home, home, dialect, nil); got != row.want {
				t.Errorf("dialect %q command %q = %q, want %q", dialect, row.command, got, row.want)
			}
		}
	}
}
