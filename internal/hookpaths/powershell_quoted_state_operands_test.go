// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The hook client lists the quoted path literals of a PowerShell call for a
// managed gateway: as their value, also inside a pwsh -Command body and
// between typographic quotes; not text that expands, and not plain words.
// Past the bound the call is described as incomplete.
func TestPowerShellQuotedPathOperandsReadEachQuotedPath(t *testing.T) {
	t.Parallel()
	cwd := t.TempDir()
	paths := func(command string) ([]string, bool) {
		operands, over := powerShellQuotedPathOperands(command, cwd)
		var out []string
		for _, operand := range operands {
			out = append(out, operand.path)
		}
		return out, over
	}
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{`$p='C:\u\lnk\config.yaml'; [IO.File]::WriteAllText($p,'x')`, []string{`C:\u\lnk\config.yaml`}},
		{`pwsh -NoProfile -Command "$p='C:\u\it''s\c.yaml'; sc -LiteralPath $p x"`, []string{`C:\u\it's\c.yaml`}},
		{`$p="C:\u\v.txt"; $q="$env:TEMP\v.txt"; '"'`, []string{`C:\u\v.txt`}},
		{"$p=\u2018C:\\u\\t.txt\u2019", []string{`C:\u\t.txt`}},
		{`Write-Output 'hello world' "plain"`, nil},
	} {
		got, over := paths(tc.command)
		var want []string
		for _, path := range tc.want {
			want = append(want, OperandPath(path, cwd))
		}
		if over || !slices.Equal(got, want) {
			t.Errorf("%q: paths %q over=%t, want %q", tc.command, got, over, want)
		}
	}
	var many strings.Builder
	for i := 0; i <= powerShellQuotedPathMax; i++ {
		many.WriteString(`'C:\d\` + strconv.Itoa(i) + `.txt' `)
	}
	if got, over := paths(many.String()); !over || len(got) != powerShellQuotedPathMax {
		t.Errorf("past the bound: %d paths over=%t, want %d and over", len(got), over, powerShellQuotedPathMax)
	}
}
