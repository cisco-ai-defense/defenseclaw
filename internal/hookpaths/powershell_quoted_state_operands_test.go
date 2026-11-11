// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
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

// A write whose walk ends in the state tree spelled from where that tree
// really is (the home's .defenseclaw a link to another folder) is listed with
// the state name; a file next to the state tree is not.
func TestStateReachNamesTheStateWhereItsWalkSpellsItElsewhere(t *testing.T) {
	t.Parallel()
	home, real := t.TempDir(), t.TempDir()
	for _, name := range []string{"config.yaml", "other.yaml"} {
		dir := real
		if name == "other.yaml" {
			dir = filepath.Dir(real)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(real, filepath.Join(home, ".defenseclaw")); err != nil {
		t.Skip("no links here:", err)
	}
	links := shellLinks{known: true}
	protected := newProtectedFiles(home)
	want := filepath.Join(home, ".defenseclaw", "config.yaml")
	if got, ok := links.stateReach(filepath.Join(real, "config.yaml"), home, protected); !ok || got != want {
		t.Errorf("state file by its walked spelling: %q %t, want %q", got, ok, want)
	}
	if got, ok := links.stateReach(filepath.Join(filepath.Dir(real), "other.yaml"), home, protected); ok {
		t.Errorf("file next to the state tree placed in it: %q", got)
	}
}
