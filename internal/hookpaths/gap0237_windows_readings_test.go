// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-6:GAP-0237 item 1 (IN-fc-winnewline-REVIEW.md must-fix 1): the
// Windows scan kept the backslash of a here-document delimiter, always
// stripped a leading -, and opened a here-document after an escaped <<,
// so the posix-hinted reading read the next lines as a body and a writer
// on them was allowed. The delimiter is now the word bash compares.
func TestWindowsHereDocDelimiterAsBashReadsIt(t *testing.T) {
	const home = `C:\Users\b00`
	const writer = `powershell -c "Add-Content -Path .ssh/authorized_k* -Value k"`
	dialects := []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX}
	for _, eol := range []string{"\n", "\r\n"} {
		for _, lines := range [][]string{
			{`cat <<\EOF`, "hi", "EOF", writer},
			{"cat << -EOF", "hi", "-EOF", writer},
			{`echo a\<<b`, writer},
			{"echo 'x'", writer},
		} {
			command := strings.Join(lines, eol)
			for _, dialect := range dialects {
				if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "protected-target" {
					t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
				}
			}
		}
		for _, lines := range [][]string{
			{"python3 - <<'PY'", "import os", "print(os.getcwd())", "PY"},
			{"cat > notes.txt <<EOF", "hello world", "EOF"},
			{"cat <<-\"END\"", "\tsome text", "\tEND", "git status"},
			{`cat <<\EOF > notes.txt`, "plain text", "EOF", "git status"},
			{"cat <<- EOF", "\tx", "\tEOF", "git status"},
		} {
			command := strings.Join(lines, eol)
			for _, dialect := range dialects {
				if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "" {
					t.Errorf("dialect %q %q = %q, want allow", dialect, command, got)
				}
			}
		}
	}
	for _, row := range []struct{ command, want string }{
		{"cat <<\\EOF\nhi\nEOF\ncp a b", "cat << \\EOF hi EOF ; cp a b"},
		{"cat << -EOF\nhi\n-EOF\ncp a b", "cat << -EOF hi -EOF ; cp a b"},
		{"cat <<-EOF\nhi\n\tEOF\ncp a b", "cat << -EOF hi EOF ; cp a b"},
		{"echo a\\<<b\ncp a b", "echo a\\ << b ; cp a b"},
		{"cat <<'EOF'\nhi\nEOF\ncp a b", "cat << EOF hi EOF ; cp a b"},
	} {
		scan := actionWindowsScan(row.command, actionWindowsPlainGrammar)
		if got := strings.Join(scan.words, " "); got != row.want {
			t.Errorf("plain scan(%q) = %q, want %q", row.command, got, row.want)
		}
	}
}

// rel-1-0-6:GAP-0237 item 2 (review must-fix 2): PowerShell evaluates a
// grouping anywhere in an unquoted part of a print argument, not only at
// the start of the word; its writer is checked as a command.
func TestWindowsNestedPrintArgumentAnywhereInTheWord(t *testing.T) {
	const home = `C:\Users\b00`
	const w = `Add-Content -Path '.ssh/authorized_k*' -Value 'k'`
	dialects := []actionfacts.Dialect{"", actionfacts.DialectPowerShell}
	for _, command := range []string{
		"echo ,(" + w + ")",
		"echo 'x',(" + w + ")",
		"echo x(" + w + ")",
		"Write-Output -InputObject:(" + w + ")",
		"Write-Host a,@(" + w + ")",
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "protected-target" {
				t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
			}
		}
	}
	for _, command := range []string{
		"echo (Get-Date)",
		"echo x,(Get-Date)",
		"Write-Output \"a(b)\"",
		"echo 'f(x)'",
		"echo f(x)",
		"Write-Output -InputObject:(git status)",
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", dialect, command, got)
			}
		}
	}
}

// rel-1-0-6:GAP-0237 item 3: the plain reading had no escape rule, so in
// a Git Bash call an escaped quote opened a string that ran over the next
// lines and a writer on them read as text. The Git Bash backslash reading
// (posix hint or unknown dialect) ends that string where bash does.
func TestWindowsGitBashBackslashReading(t *testing.T) {
	const home = `C:\Users\b00`
	const writer = `powershell -c "Add-Content -Path .ssh/authorized_k* -Value k"`
	dialects := []actionfacts.Dialect{"", actionfacts.DialectPOSIX}
	for _, eol := range []string{"\n", "\r\n"} {
		for _, lines := range [][]string{
			{`echo it\'s`, writer, "echo '"},
			{`echo \"`, writer, `echo "`},
		} {
			command := strings.Join(lines, eol)
			for _, dialect := range dialects {
				if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "protected-target" {
					t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
				}
			}
		}
	}
	for _, command := range []string{
		`echo it\'s ok`,
		`echo \"quoted\"`,
		`git commit -m "say \"hi\""`,
		"echo it\\'s\ngit status",
		"git log --oneline \\\n  -3",
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", dialect, command, got)
			}
		}
	}
	for _, row := range []struct{ command, want string }{
		{"echo it\\'s\ncp a b", "echo it's ; cp a b"},
		{"echo \"a\\\"b\"\ncp a b", "echo a\"b ; cp a b"},
		{"echo a \\\ncp a b", "echo a cp a b"},
	} {
		scan := actionWindowsScan(row.command, actionWindowsPlainGrammar|actionWindowsBackslashEscapes)
		if got := strings.Join(scan.words, " "); !scan.ok || got != row.want {
			t.Errorf("backslash scan(%q) = %q ok=%v, want %q", row.command, got, scan.ok, row.want)
		}
	}
}
