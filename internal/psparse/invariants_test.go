// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// hasHardUnsafe reports whether s contains a value-changing / homoglyph rune
// (backtick, a control rune, or any non-ASCII rune) that must never appear in a
// value LiteralString reports as static.
func hasHardUnsafe(s string) bool {
	for _, r := range s {
		if r == '`' || r < 0x20 || r > 0x7e {
			return true
		}
	}
	return false
}

// FuzzStaticInvariants asserts the review-4 safety invariants on arbitrary
// input: (1) no value LiteralString returns as static contains a hard-unsafe
// rune (the Static-value allowlist is never bypassed), (2) no nested script is
// Static with empty Text, and (3) every non-static nested script carries a
// reason. It never checks pwsh; it checks psparse's own contract.
func FuzzStaticInvariants(f *testing.F) {
	for _, s := range []string{
		`Remove-Item C:\x`, "i`ex 'x'", `@{a=1;b=Remove-Item C:\x}`,
		`powershell -Version 2 -c Remove-Item C:\x`, `'a','b' | iex`,
		"Remove-Item \u2018C:\\a\u2019\u2018b\u2019", `cmd /c "del a & del b"`,
		`powershell -W` + "`" + `indowStyle Hidden -c x`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		sc, _ := Parse(src, Options{})
		WalkCommands(sc, func(c *Command) {
			if v, ok := LiteralString(c.Name); ok && hasHardUnsafe(v) {
				t.Fatalf("static command name %q has a hard-unsafe rune (src %q)", v, src)
			}
			for _, el := range c.Elements {
				var e Expr
				switch x := el.(type) {
				case *Arg:
					e = x.Value
				case *Parameter:
					e = x.Colon
				case Expr:
					e = x
				}
				if e == nil {
					continue
				}
				if v, ok := LiteralString(e); ok && hasHardUnsafe(v) {
					t.Fatalf("static element %q has a hard-unsafe rune (src %q)", v, src)
				}
				if items, ok := LiteralList(e); ok {
					for _, it := range items {
						if it.Static && hasHardUnsafe(it.Text) {
							t.Fatalf("static list element %q has a hard-unsafe rune (src %q)", it.Text, src)
						}
					}
				}
			}
		})
		for _, n := range ExtractNestedScripts(sc) {
			if n.Static && n.Text == "" {
				t.Fatalf("nested script Static with empty text (src %q)", src)
			}
			if !n.Static && n.Reason == "" {
				t.Fatalf("non-static nested script has no reason (src %q)", src)
			}
		}
	})
}
