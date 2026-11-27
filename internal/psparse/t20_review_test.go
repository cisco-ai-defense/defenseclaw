// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// TestT20HereStringSubexprEndRespectsEscapesAndQuotes (DET111 T20 review
// P1-2, P2-4): an expandable here-string finds the end of a $( ) as pwsh
// does, so a backtick-escaped `$( or a $( inside a quoted string does not
// open a group that never closes and swallows the rest of the script. A $( )
// that really never closes falls back to the first terminator line (the
// 1.0.10 reading) with a ps_unterminated diagnostic, and an unterminated
// string or here-string is never a clean parse. Red at 23ee0d55e2.
func TestT20HereStringSubexprEndRespectsEscapesAndQuotes(t *testing.T) {
	tail := "Remove-Item -Recurse -Force C:\\"
	cases := []struct {
		name, src string
		want      []string // command names the reader must see
		diag      bool     // a ps_unterminated diagnostic is expected
	}{
		{"backtick escaped subexpr (reviewer row 1)", "$s = @\"\ncost `$(5\n\"@\n" + tail, []string{"remove-item"}, false},
		{"quoted subexpr text (reviewer row 2)", "$s = @\"\ncost $('$(')\n\"@\n" + tail, []string{"remove-item"}, false},
		{"double quoted paren in subexpr", "$s = @\"\n$(\"a)b\" + 'x')\n\"@\n" + tail, []string{"remove-item"}, false},
		{"escaped quote in nested string", "$s = @\"\n$(\"a`\"b\")\n\"@\n" + tail, []string{"remove-item"}, false},
		{"line comment in subexpr", "$s = @\"\n$(1 # ) $(\n)\n\"@\n" + tail, []string{"remove-item"}, false},
		{"block comment in subexpr", "$s = @\"\n$(1 <# $( #>)\n\"@\n" + tail, []string{"remove-item"}, false},
		{"plain parens in subexpr", "$s = @\"\n$((1+2) * (3))\n\"@\n" + tail, []string{"remove-item"}, false},
		{"nested here-string (GAP-1853)", "$s = @\"\n$(@\"\nx\n\"@)\n\"@\n" + tail, []string{"remove-item"}, false},
		{"controls stay", "$s = @\"\ncost $(Get-Date)\n\"@\n" + tail, []string{"get-date", "remove-item"}, false},
		{"unclosed subexpr falls back to the first terminator", "$s = @\"\ncost $(5\n\"@\n" + tail, []string{"remove-item"}, true},
		{"unclosed quote in subexpr falls back", "$s = @\"\ncost $('5)\n\"@\n" + tail, []string{"remove-item"}, true},
		{"unterminated here-string", "$s = @\"\ncost\n" + tail, nil, true},
		{"unterminated double string (P2-4)", "Write-Output ready; \"abc", []string{"write-output"}, true},
		{"unterminated single string (P2-4)", "Write-Output ready; 'abc", []string{"write-output"}, true},
		{"unterminated block comment (P2-4)", "Write-Output ready; <# abc", []string{"write-output"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			miss, got := missingCommands(c.src, c.want)
			if len(miss) > 0 {
				t.Errorf("reader misses %q (want %q, reader %q)", miss, c.want, got)
			}
			sc, _ := Parse(c.src, Options{})
			has := false
			for _, d := range sc.Diagnostics {
				if d.Reason == ReasonUnterminated {
					has = true
				}
			}
			if has != c.diag {
				t.Errorf("ps_unterminated diagnostic = %v, want %v (diags %+v)", has, c.diag, sc.Diagnostics)
			}
		})
	}
}
