// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap0234SecondLineWriters write the keys file through a quoted pattern
// from the home folder: PowerShell expands the wildcard of a cmdlet -Path
// and Remove-Item, and the alias and MSYS tools read their own pattern.
var gap0234SecondLineWriters = []string{
	`Add-Content -Path '.ssh/authorized_k*' -Value 'k'`,
	`Set-Content '.ssh/authorized_k*' 'ssh-ed25519 AAAA'`,
	`Remove-Item '.ssh/authorized_k*'`,
	`cp a.txt '.ssh/authorized_k*'`,
	`Copy-Item a.txt '.ssh/authorized_k*'`,
	`cp.exe a.txt '.ssh/authorized_k*'`,
	`mv a.txt '.ssh/authorized_k*'`,
	`rm '.ssh/authorized_k*'`,
	`install a.txt '.ssh/authorized_k*'`,
	`tee.exe '.ssh/authorized_k*' < a.txt`,
}

// rel-1-0-6:GAP-0234: the Windows scan did not end a statement at an
// unquoted line end, so a first echo or Write-Output statement read the
// quoted words of every later line as text and a writer on a later line
// was allowed. Each line is now its own statement in every Windows
// reading; the same writer on one line after a ; already blocked.
func TestWindowsLineEndEndsStatement(t *testing.T) {
	const home = `C:\Users\b00`
	dialects := []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX}
	for _, first := range []string{"echo 'x'", "Write-Output 'x'", "echo hi", "Write-Output 'a'\necho 'b'"} {
		for _, eol := range []string{"\n", "\r\n", "\n\n", " \r\n  "} {
			for _, writer := range gap0234SecondLineWriters {
				command := first + eol + writer
				single := first + "; " + writer
				for _, dialect := range dialects {
					if got := ActionCommandDecisionWithDialectAndGlobFacts(single, home, home, dialect, nil); got != "protected-target" {
						t.Fatalf("dialect %q %q = %q, want protected-target (one line)", dialect, single, got)
					}
					if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "protected-target" {
						t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
					}
				}
			}
		}
	}
	benign := []string{
		"echo hi\ngit status",
		"echo hi\r\ngit status",
		"Write-Output 'done'\nls",
		"Write-Output 'done'\r\nGet-ChildItem",
		"echo '*'\necho done",
		"echo \"line one\nline two\"\ngit log --oneline -3",
		"Write-Output @'\nrun cp a.txt b.txt\nthen rm b.txt\n'@\ngit status",
		"Write-Output 'a' `\n  'b'",
		"git commit -m 'msg' `\r\n  --allow-empty",
		"Get-ChildItem |\n  Select-Object Name",
		"Get-ChildItem\n| Select-Object Name",
		"git status\r\n\r\ngit diff --stat\r\n",
		"cp a.txt b.txt\nWrite-Output 'copied'",
	}
	for _, command := range benign {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", dialect, command, got)
			}
		}
	}
}

// The scan emits a ; at an unquoted line end, and not inside quotes, a
// here-string, after a continuing operator or before a leading pipe.
func TestWindowsScanLineEndSeparator(t *testing.T) {
	for _, row := range []struct {
		command string
		grammar actionWindowsGrammar
		want    string
	}{
		{"echo 'x'\ncp a b", 0, "echo x ; cp a b"},
		{"echo 'x'\r\ncp a b", 0, "echo x ; cp a b"},
		{"echo 'x'\rcp a b", 0, "echo x ; cp a b"},
		{"echo 'x'\n\n\ncp a b\n", 0, "echo x ; cp a b ;"},
		{"echo 'x\ny'\ncp a b", 0, "echo x\ny ; cp a b"},
		{"echo x |\ncp a b", 0, "echo x | cp a b"},
		{"echo x\n  | cp a b", 0, "echo x | cp a b"},
		{"echo x `\ncp a b", 0, "echo x cp a b"},
		{"echo x # note\ncp a b", 0, "echo x ; cp a b"},
		{"echo x\ncp a b", actionWindowsPlainGrammar, "echo x ; cp a b"},
		{"echo x \\\ncp a b", actionWindowsPlainGrammar, "echo x \\ cp a b"},
		{"echo x ^\r\ncp a b", actionWindowsPlainGrammar, "echo x ^ cp a b"},
		{"echo x\rcp a b", actionWindowsPlainGrammar, "echo x cp a b"},
		{"cat > p.txt <<'EOF'\n*** Update File: a\nEOF\ncp a b", actionWindowsPlainGrammar, "cat > p.txt << EOF *** Update File: a EOF ; cp a b"},
		{"cat <<-EOF\r\nx y\r\n\tEOF\r\ncp a b", actionWindowsPlainGrammar, "cat << -EOF x y EOF ; cp a b"},
		{"cat <<< 'x'\ncp a b", actionWindowsPlainGrammar, "cat << < x ; cp a b"},
	} {
		scan := actionWindowsScan(row.command, row.grammar)
		if got := strings.Join(scan.words, " "); !scan.ok || got != row.want {
			t.Errorf("scan(%q, %d) = %q ok=%v, want %q", row.command, row.grammar, got, scan.ok, row.want)
		}
	}
}

// The POSIX grammar of a Linux or macOS home already ends a statement at
// a line end.
func TestPosixLineEndEndsStatement(t *testing.T) {
	const home = "/home/u"
	for _, first := range []string{"echo 'x'", "printf 'x'"} {
		for _, writer := range []string{"cp a.txt .ssh/authorized_keys", "tee .ssh/authorized_keys < a.txt", "cp a.txt ~/.ssh/authorized_k*"} {
			command := first + "\n" + writer
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, actionfacts.DialectPOSIX, nil); got != "protected-target" {
				t.Errorf("%q = %q, want protected-target", command, got)
			}
		}
	}
}

// rel-1-0-6:GAP-0234 (lead, BATCH36): PowerShell runs a (...), $(...) or
// @(...) argument of echo, Write-Output or Write-Host as a nested
// statement, so a writer inside it is checked as a writer, not as text.
func TestWindowsNestedStatementOfPrintIsChecked(t *testing.T) {
	const home = `C:\Users\b00`
	dialects := []actionfacts.Dialect{"", actionfacts.DialectPowerShell}
	for _, printer := range []string{"echo", "Write-Output", "Write-Host"} {
		for _, open := range []string{"(", "$(", "@("} {
			for _, writer := range gap0234SecondLineWriters {
				command := printer + " " + open + writer + ")"
				for _, dialect := range dialects {
					if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "protected-target" {
						t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
					}
				}
			}
		}
	}
	for _, command := range []string{
		"echo (Get-Date)",
		"Write-Output $(git status)",
		"echo ('a' + 'b')",
		"Write-Host @(1, 2, 3)",
		"echo '(cp a.txt b.txt)'",
		"Write-Output \"done (ok)\"",
		"echo (Get-ChildItem -Name)\ngit status",
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", dialect, command, got)
			}
		}
	}
}
