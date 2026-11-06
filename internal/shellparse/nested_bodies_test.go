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
		{"one bash -c script of 400 KB", "bash -c '" + strings.Repeat("printf '\\''%s\\n'\\'' \"a b c\" "+strings.Repeat("word ", 400)+"; ", 200) + "'", false},
		{"bash -c of a python -c program of 40 KB", "bash -c 'python3 -c \"" + strings.Repeat("x = 1 + 2\n", 4096) + "\"'", false},
		{"ssh of a bash -c script of 60 KB", `ssh host "bash -c 'printf %s ` + strings.Repeat("a b ", 15000) + `'"`, false},
		{"flat echo of 500 KB", "echo '" + strings.Repeat("ab cd; ef ", 50000) + "'", false},
		{"here-document of 300 KB", "cat > notes.txt <<'EOF'\n" + strings.Repeat("some text (with) a b c; d | e\n", 10000) + "EOF", false},
		{"three nested of 7 KB", `bash -c 'ssh host "sh -c '\''printf %s ` + strings.Repeat("a b ", 1800) + `'\''"'`, false},
		{"three nested of 12 KB", `bash -c 'ssh host "sh -c '\''printf %s ` + strings.Repeat("a b ", 3000) + `'\''"'`, true},
		{"bash -c x8", nestedSingleQuoted(8, "bash -c", "rm -rf ~/project/output"), false},
		{"bash -c x9", nestedSingleQuoted(9, "bash -c", "rm -rf ~/project/output"), true},
	} {
		if got := NestedBodiesOverBudget(row.command); got != row.over {
			t.Errorf("%s (%d bytes): over=%v, want %v", row.name, len(row.command), got, row.over)
		}
		if got := PastReadingBounds(row.command); got != row.over {
			t.Errorf("%s: PastReadingBounds=%v, want %v", row.name, got, row.over)
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
