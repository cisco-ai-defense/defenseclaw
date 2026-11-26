// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// TestGAP1919LexicalDiagnostics (rel-1-0-10:GAP-1919): a text that ends
// inside a string, here-string or block comment has a ps_unterminated
// diagnostic (T20 review P2-4) marked Lexical, so a raise-only reader can tell
// it from a parse error the parser met (an unclosed block). The quote rows pin
// pwsh string escapes: inside "..." a backtick escapes the next rune whatever
// precedes it (a backslash is a plain rune), "" is one quote, inside single
// quotes a doubled single quote is one quote, and a backtick at the end of the
// text leaves the string open.
func TestGAP1919LexicalDiagnostics(t *testing.T) {
	bt := "\x60"
	cases := []struct {
		name, src   string
		strings     int  // string tokens the lexer reads
		diag        bool // a ps_unterminated diagnostic (an unclosed block is ps_unbalanced)
		onlyLexical bool // OnlyLexicalDiagnostics
	}{
		{"backslash then escaped quote", "Write-Output \"a\\" + bt + "\"b\\" + bt + "\"\"", 1, false, true},
		{"doubled quote", "Write-Output \"a\"\"b\"", 1, false, true},
		{"single quoted doubled quote", "Write-Output (\x27a\x27\x27b\x27)", 1, false, true},
		{"escaped quote at end", "Write-Output \"a" + bt + "\"", 0, true, true},
		{"backtick at end of input", "Write-Output \"a" + bt, 0, true, true},
		{"cut statement", "Start-Process powershell -ArgumentList \"-NoProfile -Command \\" + bt + "\"Get-Item C:\\x -Force", 0, true, true},
		{"unterminated block comment", "Write-Output ready; <# abc", 0, true, true},
		{"unclosed here-string subexpr", "$s = @\"\n$(1\n\"@\nWrite-Output x", 1, true, true},
		{"unclosed block is a parser error", "if ($a) { Write-Output x", 0, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := 0
			for _, tk := range newLexer(c.src).lex() {
				if tk.Kind == TokString {
					n++
				}
			}
			if n != c.strings {
				t.Errorf("string tokens = %d, want %d", n, c.strings)
			}
			sc, err := Parse(c.src, Options{Dialect: DialectUnknown})
			if err != nil || sc == nil {
				t.Fatalf("Parse: %v", err)
			}
			has := false
			for _, d := range sc.Diagnostics {
				if d.Reason == ReasonUnterminated {
					has = true
				}
			}
			if has != c.diag {
				t.Errorf("ps_unterminated = %v, want %v (%+v)", has, c.diag, sc.Diagnostics)
			}
			if got := sc.OnlyLexicalDiagnostics(); got != c.onlyLexical {
				t.Errorf("OnlyLexicalDiagnostics = %v, want %v (%+v)", got, c.onlyLexical, sc.Diagnostics)
			}
		})
	}
}
