// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// TestGAP1655CommandLineWords: a child command line is split into words by
// the CommandLineToArgvW rules (rel-1-0-10:GAP-1655, GAP-1660).
func TestGAP1655CommandLineWords(t *testing.T) {
	for _, c := range []struct {
		text string
		want []string
	}{
		{`"a b"`, []string{`a b`}},
		{`"a \"b\" c"`, []string{`a "b" c`}},
		{`"C:\x\y"`, []string{`C:\x\y`}},
		{`"C:\work\\"`, []string{`C:\work\`}},
		{`"a\\\"b"`, []string{`a\"b`}},
		{`""`, []string{``}},
		{`"a" "b"`, []string{`a`, `b`}},
		{`"a""b"`, []string{`a"b`}},
		{`"a\"`, []string{`a"`}},
		{`"a`, []string{`a`}},
		{`a"`, []string{`a`}},
		{`a\\b  c\`, []string{`a\\b`, `c\`}},
		{" a\t b ", []string{`a`, `b`}},
		{"\"x\ny\" z", []string{"x\ny", `z`}},
	} {
		if got := commandLineWords(c.text); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.text, got, c.want)
		}
	}
}

// TestGAP1660CommandLineBodyJoinsTheWords: a -Command body that starts with
// a double quote is the child's words after -Command joined with blanks, as
// powershell.exe runs it; before, only a body that was one quoted word was
// taken apart, and "iex x" "y", "a" ; "b" or "a""b" were read as written,
// string expressions that run nothing (rel-1-0-10:GAP-1660). A body whose
// first word is not quoted stays as written (rel-1-0-10:GAP-1638).
func TestGAP1660CommandLineBodyJoinsTheWords(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		{`"a b"`, `a b`},
		{`"iex x" "y"`, `iex x y`},
		{`"Remove-Item" ; "C:\x"`, `Remove-Item ; C:\x`},
		{`"a""b"`, `a"b`},
		{`Get-ItemProperty "HKCU:\Software\MyApp"`, `Get-ItemProperty "HKCU:\Software\MyApp"`},
		{`Write-Output "a" "b"`, `Write-Output "a" "b"`},
		{`""`, `""`},
		{`"" ""`, `"" ""`},
		{`Get-Date; Write-Output done`, `Get-Date; Write-Output done`},
		{`Write-Output   a`, `Write-Output   a`},
	} {
		if got := commandLineBody(c.body); got != c.want {
			t.Errorf("%s: %q, want %q", c.body, got, c.want)
		}
	}
}
