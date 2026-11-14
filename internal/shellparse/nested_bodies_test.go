// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"strings"
	"testing"
)

func nestedSingleQuoted(levels int, program, inner string) string {
	for i := 0; i < levels; i++ {
		inner = program + " '" + strings.ReplaceAll(inner, "'", `'\''`) + "'"
	}
	return inner
}

func nestedDoubleQuoted(levels int, program, inner string) string {
	escape := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`")
	for i := 0; i < levels; i++ {
		inner = program + ` "` + escape.Replace(inner) + `"`
	}
	return inner
}

func nestedHereDocs(levels int, inner string) string {
	for i := levels; i > 0; i-- {
		tag := "B" + strings.Repeat("X", i)
		inner = "bash <<'" + tag + "'\n" + inner + "\n" + tag
	}
	return inner
}

// GAP-0677: nested shell bodies past MaxNestedBodyBytes are past the
// reading bounds, whatever program carries them (bash -c, sh -c, eval,
// env, a here-document), and ordinary large commands are not.
func TestNestedBodiesOverBudget(t *testing.T) {
	long := strings.Repeat("echo one two three four five six seven eight; ", 20)
	for _, row := range []struct {
		name    string
		command string
		over    bool
	}{
		{"bash -c x11", nestedSingleQuoted(11, "bash -c", "rm -rf ~/project/output"), true},
		{"bash -c x10 with a PowerShell tail", nestedSingleQuoted(10, "bash -c", `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/project/output`), true},
		{"sh -c x13 double quoted", nestedDoubleQuoted(13, "sh -c", "rm -rf ~/project/output"), true},
		{"eval x13", nestedDoubleQuoted(13, "eval", "rm -rf ~/project/output"), true},
		{"env bash -c x10", nestedSingleQuoted(10, "env bash -c", "rm -rf ~/project/output"), true},
		{"here-documents x6", nestedHereDocs(6, strings.Repeat(long, 6)), true},
		{"bash -c x6 of a long body", nestedSingleQuoted(6, "bash -c", strings.Repeat(long, 6)), true},

		{"short nested", nestedSingleQuoted(6, "bash -c", "rm -rf ~/project/output"), false},
		// A 400 KB flat script is past the reading budget (tokens and parsed
		// nodes); the largest ordinary one is about 60 KB.
		{"one bash -c script of 60 KB", "bash -c '" + strings.Repeat("printf '\\''%s\\n'\\'' \"a b c\" "+strings.Repeat("word ", 400)+"; ", 30) + "'", false},
		{"bash -c of a python -c program of 40 KB", "bash -c 'python3 -c \"" + strings.Repeat("x = 1 + 2\n", 4096) + "\"'", false},
		// 60 KB of operands is also past the reading budget (parsed nodes,
		// shellparse.MaxParsedNodes): the row is the largest ordinary script
		// inside it, 20,000 nodes.
		{"ssh of a bash -c script of 20 KB", `ssh host "bash -c 'printf %s ` + strings.Repeat("a b ", 5000) + `'"`, false},
		{"flat echo of 500 KB", "echo '" + strings.Repeat("ab cd; ef ", 50000) + "'", false},
		{"here-document of 300 KB", "cat > notes.txt <<'EOF'\n" + strings.Repeat("some text (with) a b c; d | e\n", 10000) + "EOF", false},
		{"three nested of 7 KB", `bash -c 'ssh host "sh -c '\''printf %s ` + strings.Repeat("a b ", 1800) + `'\''"'`, false},
		{"three nested of 12 KB", `bash -c 'ssh host "sh -c '\''printf %s ` + strings.Repeat("a b ", 3000) + `'\''"'`, false},
		{"three nested of 20 KB", `bash -c 'ssh host "sh -c '\''printf %s ` + strings.Repeat("a b ", 5000) + `'\''"'`, true},
		{"bash -c x8", nestedSingleQuoted(8, "bash -c", "rm -rf ~/project/output"), false},
		{"bash -c x9", nestedSingleQuoted(9, "bash -c", "rm -rf ~/project/output"), false},
		{"bash -c x10", nestedSingleQuoted(10, "bash -c", "rm -rf ~/project/output"), true},
	} {
		if got := NestedBodiesOverBudget(row.command); got != row.over {
			t.Errorf("%s (%d bytes): over=%v, want %v", row.name, len(row.command), got, row.over)
		}
		if got := PastReadingBounds(row.command); got != row.over {
			t.Errorf("%s: PastReadingBounds=%v, want %v", row.name, got, row.over)
		}
	}
	for _, row := range []struct {
		name     string
		command  string
		min, max int
	}{
		{"bash -c x8", nestedSingleQuoted(8, "bash -c", "rm -rf ~/project/output"), 0, MaxNestedBodyProofBytes},
		{"bash -c x9", nestedSingleQuoted(9, "bash -c", "rm -rf ~/project/output"), MaxNestedBodyProofBytes + 1, MaxNestedBodyBytes},
		{"short", "bash -c 'rm -rf output'", 0, 0},
	} {
		if got := NestedBodyWeight(row.command); got < row.min || got > row.max {
			t.Errorf("%s: NestedBodyWeight=%d, want %d..%d", row.name, got, row.min, row.max)
		}
	}
	if !PastReadingBounds(strings.Repeat("(", MaxNestingDepth+1)) {
		t.Error("a command past MaxNestingDepth is within the reading bounds")
	}
}

func TestUnescapeLiteral(t *testing.T) {
	for _, row := range []struct {
		value, want string
		double      bool
	}{
		{`a\ b\'c`, `a b'c`, false},
		{`a\"b\\c\$d\e`, `a"b\c$d\e`, true},
		{"a\\\nb", "ab", false},
		{`trailing\`, `trailing\`, false},
	} {
		if got := unescapeLiteral(row.value, row.double); got != row.want {
			t.Errorf("unescapeLiteral(%q, %v) = %q, want %q", row.value, row.double, got, row.want)
		}
	}
}

// TestNestedBodyBehindWrappersIsCode pins review finding 6 of parselimits-2:
// a shell body that is past the reading budget is over the nested bound when
// a shell runs it, directly, behind sudo, env, nohup and their options, or
// as a here-document fed to the shell; the same text given to a program
// that only reads it (echo, cat) is not.
func TestNestedBodyBehindWrappersIsCode(t *testing.T) {
	body := strings.Repeat("a | ", 1200) + "a"
	if BudgetExceeded(body) == "" {
		t.Fatal("the body is within the budget")
	}
	for _, row := range []struct {
		name    string
		command string
		over    bool
	}{
		{"bash -c", "bash -c '" + body + "'", true},
		{"sudo bash -c", "sudo bash -c '" + body + "'", true},
		{"sudo -u user bash -c", "sudo -n -u user bash -c '" + body + "'", true},
		{"env A=b bash -c", "env A=b -i bash -c '" + body + "'", true},
		{"env -u NAME sh -c", "env -u NAME sh -c '" + body + "'", true},
		{"nohup nice -n 5 bash -c", "nohup nice -n 5 bash -c '" + body + "'", true},
		{"timeout 5 bash -c", "timeout 5 bash -c '" + body + "'", true},
		{"/usr/bin/sudo /bin/bash -c", "/usr/bin/sudo /bin/bash -c '" + body + "'", true},
		{"here-document fed to bash", "bash <<'EOF'\n" + body + "\nEOF\n", true},
		{"here-document fed to sudo bash", "sudo bash <<'EOF'\n" + body + "\nEOF\n", true},
		{"echo", "echo '" + body + "'", false},
		{"sudo echo", "sudo echo '" + body + "'", false},
		{"here-document fed to cat", "cat <<'EOF'\n" + body + "\nEOF\n", false},
	} {
		if got := NestedBodiesOverBudget(row.command); got != row.over {
			t.Errorf("%s (%d bytes): over=%v, want %v", row.name, len(row.command), got, row.over)
		}
	}
}

// TestSelfNamingBodyIsNotNested pins GAP-0381: a static word that is its own
// body ($ is a shell word) is not a nested body of itself at every level
// down to the depth bound, so a command of any size that carries one (or a
// 4 KiB comment next to a sed program that starts with one) weighs nothing.
func TestSelfNamingBodyIsNotNested(t *testing.T) {
	for _, size := range []int{nestedBodyMinCommand - 40, nestedBodyMinCommand, 8 << 10, 70 << 10} {
		for name, command := range map[string]string{
			"sed program": "sed -i '$ a x y z' ~/.ssh/authorized_keys\n# " + strings.Repeat("x", size),
			"echo":        "echo '$ a b c'\n" + strings.Repeat(":\n", size/2),
			"dollar":      "echo '$ a b' $ $ $\n# " + strings.Repeat("x", size),
		} {
			if weight := NestedBodyWeight(command); weight != 0 {
				t.Errorf("%s size=%d: NestedBodyWeight=%d, want 0", name, size, weight)
			}
		}
	}
}
