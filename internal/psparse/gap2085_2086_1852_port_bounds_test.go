// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"testing"
)

// TestNestingOverIgnoresCommentsAndStrings (GAP-2085): brackets in a comment,
// a verbatim string or here-string, or the literal text of an expandable
// string do not nest, so 8193 of them do not make the port decline; 8193 real
// nested brackets, in code or in the $( ) of an expandable string, still do.
// Red at det111/engine-train-6 f9b5854812 (nestingOver counted every bracket).
func TestNestingOverIgnoresCommentsAndStrings(t *testing.T) {
	open := strings.Repeat("(", maxPortNesting+1)
	shut := strings.Repeat(")", maxPortNesting+1)
	inert := map[string]string{
		"line-comment":       "Write-Output ok # " + open + "\nWrite-Output done",
		"comment-after-op":   "$x =# " + open + "\nWrite-Output done",
		"block-comment":      "Write-Output ok <# " + open + " #> done",
		"single-quoted":      "Write-Output '" + open + "''s' done",
		"double-quoted":      `Write-Output "` + open + `""x" done`,
		"escaped-in-dq":      "Write-Output \"`$" + open + "\" done",
		"single-here-string": "Write-Output @'\n" + open + "\n'@\nWrite-Output done",
		"double-here-string": "Write-Output @\"\n" + open + "\n\"@\nWrite-Output done",
		"smart-quoted":       "Write-Output \u2018" + open + "\u2019 done",
		"escaped-in-code":    "Write-Output " + strings.Repeat("`(", maxPortNesting+1) + " done",
	}
	for name, src := range inert {
		if nestingOver(src, maxPortNesting) {
			t.Errorf("%s: brackets that do not nest counted as nesting", name)
		}
		if _, ok := FromPwshparse(src, Options{}); !ok {
			t.Errorf("%s: the port declined a script whose brackets do not nest", name)
		}
	}
	real := map[string]string{
		"code":                    open + "1" + shut,
		"dq-subexpression":        `Write-Output "$(` + open + "1" + shut + `)"`,
		"here-string-subexpr":     "Write-Output @\"\n$(" + open + "1" + shut + ")\n\"@",
		"after-closed-string":     "Write-Output 'a' \"b\" " + open + "1" + shut,
		"after-comment":           "# c (((\n" + open + "1" + shut,
		"after-unclosed-dq-subex": `Write-Output "$(` + open,
		"braces":                  strings.Repeat("{", maxPortNesting+1),
		"hash-glued-to-word":      "Write-Output a#" + open,
	}
	for name, src := range real {
		if !nestingOver(src, maxPortNesting) {
			t.Errorf("%s: nesting past maxPortNesting not counted", name)
		}
	}
	if nestingOver(`Write-Output "$((1))" (2) '(' # (`, 3) {
		t.Error("shallow script with brackets in strings and a comment reads as deep")
	}
}

// TestPortTruncationBoundIsOneRule (GAP-2086): one byte bound decides a
// truncated reading for both readers. An input of maxInput bytes or more is
// read by Parse (its first maxInput bytes, a ReasonTruncated diagnostic) and
// the port declines it; one byte less is the port's, with no truncated
// diagnostic. Red at det111/engine-train-6 f9b5854812 (the port read an input
// of exactly maxInput bytes itself).
func TestPortTruncationBoundIsOneRule(t *testing.T) {
	prefix := "Remove-Item C:\\Users\\alice\\proj\\o.txt\n"
	for _, n := range []int{maxInput - 1, maxInput, maxInput + 1} {
		src := prefix + "#" + strings.Repeat("x", n-len(prefix)-1)
		if len(src) != n {
			t.Fatalf("fixture length %d, want %d", len(src), n)
		}
		truncated := n >= maxInput
		if _, ok := FromPwshparse(src, Options{}); ok == truncated {
			t.Errorf("len %d: port read=%v, want %v", n, ok, !truncated)
		}
		sc, port, err := ParseEffects(src, Options{})
		if err != nil || sc == nil {
			t.Fatalf("len %d: ParseEffects err=%v", n, err)
		}
		if port == truncated {
			t.Errorf("len %d: port=%v, want %v", n, port, !truncated)
		}
		got := false
		for _, d := range sc.Diagnostics {
			got = got || d.Reason == ReasonTruncated
		}
		if got != truncated {
			t.Errorf("len %d: truncated diagnostic %v, want %v", n, got, truncated)
		}
		if len(sc.Statements) == 0 {
			t.Errorf("len %d: the reading dropped the Remove-Item statement", n)
		}
	}
}

// TestGAP1852HashAfterOperatorIsComment: a '#' (or '<#') that starts a token
// after an operator is a comment, as in the real parser, so the text after it
// is not read as commands, and the commands the real parser reads are read.
// Expected command names are pwsh 7.6.6's (scripts/pwshoracle/fixture rows
// pw-01a2b1a357 pw-759328ff09 pw-9a1b311d1d pw-abd0522ef6 pw-d3e3663449
// pw-076ce5eee9 pw-12ef482d6c, and benign twins). Red at a64bfdb931; fixed by
// the GAP-1850 lexer change (3ccf02a824), pinned here for both readers.
func TestGAP1852HashAfterOperatorIsComment(t *testing.T) {
	cases := []struct {
		src  string
		want []string
	}{
		{"$x =#    Remove-Item -Recurse -Force C:\\decoy\nWrite-Output ok", []string{"write-output"}},
		{"$x =# ; Remove-Item -Recurse -Force C:\\decoy\nWrite-Output ok", []string{"write-output"}},
		{"$x =<# note #>1; Remove-Item -Recurse -Force C:\\", []string{"remove-item"}},
		{"$x =<# note #>1", nil},
		{"]<#x#>; Remove-Item -Recurse -Force C:\\", []string{"]", "remove-item"}},
		{"Write-Output (=a   #    Remove-Item -Recurse -Force C:\\", []string{"write-output", "=a"}},
		{"Write-Output $(*a   #    Remove-Item -Recurse -Force $HOME\\.defenseclaw", []string{"write-output", "*a"}},
		// twins: a command after the comment line, and a glued '#' that is word text
		{"$x =# c\nRemove-Item -Recurse -Force C:\\decoy", []string{"remove-item"}},
		{"$x = 1 # note", nil},
		{"Write-Output a#b; Remove-Item x", []string{"write-output", "remove-item"}},
	}
	names := func(sc *Script) []string {
		var got []string
		for _, inv := range Project(sc) {
			got = append(got, strings.ToLower(inv.Name))
		}
		return got
	}
	for _, c := range cases {
		sc, err := Parse(c.src, Options{})
		if err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		if got := names(sc); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("Parse %q: commands %q, want %q", c.src, got, c.want)
		}
		if sc, port, _ := ParseEffects(c.src, Options{}); port {
			if got := names(sc); strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("port %q: commands %q, want %q", c.src, got, c.want)
			}
		}
	}
}
