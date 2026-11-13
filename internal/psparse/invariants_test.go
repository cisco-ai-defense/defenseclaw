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

// invariantSeeds exercise the allowlist, hashtable, host, iex and Start-Process
// paths plus the review-5 legacy-quoting / wildcard cases.
var invariantSeeds = []string{
	`Remove-Item C:\x`, "i`ex 'x'", `@{a=1;b=Remove-Item C:\x}`,
	`powershell -Version 2 -c Remove-Item C:\x`, `'a','b' | iex`,
	"Remove-Item \u2018C:\\a\u2019\u2018b\u2019", `cmd /c "del a & del b"`,
	`powershell -W` + "`" + `indowStyle Hidden -c x`, `Remove-Item "/home/u/.ss[h]"`,
	`powershell -c 'New-Item C:\w -Value "a;Remove-Item C:\Windows"'`,
	`Start-Process powershell -ArgumentList '-c','Remove-Item C:\x'`,
	`@{a=foreach($i in Remove-Item C:\Windows){1}}`, `powershell 00-` + "\xe8",
}

// assertStaticLeafSafe walks a parsed script and fails if any value
// LiteralString reports static carries a hard-unsafe rune, if a nested script
// is Static with empty text, or if a non-static nested script has no reason.
// For a static PowerShell-dialect nested script it re-parses the text under the
// same dialect (up to depth 2) and re-checks the leaves.
func assertStaticLeafSafe(t *testing.T, sc *Script, src string, d Dialect, depth int) {
	WalkCommands(sc, func(c *Command) {
		if v, ok := LiteralString(c.Name); ok && hasHardUnsafe(v) {
			t.Fatalf("d=%d depth=%d static name %q hard-unsafe (src %q)", d, depth, v, src)
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
				t.Fatalf("d=%d depth=%d static element %q hard-unsafe (src %q)", d, depth, v, src)
			}
			if items, ok := LiteralList(e); ok {
				for _, it := range items {
					if it.Static && hasHardUnsafe(it.Text) {
						t.Fatalf("d=%d depth=%d static list element %q hard-unsafe (src %q)", d, depth, it.Text, src)
					}
				}
			}
		}
	})
	for _, n := range ExtractNestedScripts(sc) {
		if n.Static && n.Text == "" {
			t.Fatalf("d=%d depth=%d nested Static with empty text (src %q)", d, depth, src)
		}
		if !n.Static && n.Reason == "" {
			t.Fatalf("d=%d depth=%d non-static nested has no reason (src %q)", d, depth, src)
		}
		if n.Static && n.Dialect == "powershell" && depth < 2 {
			sub, _ := Parse(n.Text, Options{Dialect: d})
			assertStaticLeafSafe(t, sub, n.Text, d, depth+1)
		}
	}
}

// FuzzStaticInvariants checks the leaf-safety and nested invariants under every
// dialect (Pwsh7, Unknown, Windows PowerShell 5.1).
func FuzzStaticInvariants(f *testing.F) {
	for _, s := range invariantSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		for _, d := range []Dialect{DialectPwsh7, DialectUnknown, DialectWindowsPS51} {
			sc, _ := Parse(src, Options{Dialect: d})
			assertStaticLeafSafe(t, sc, src, d, 0)
		}
	})
}

// FuzzRev5Inv is the review-5 contract fuzzer: it checks the effects-facing
// invariants under the dialects effects actually passes (Unknown and 5.1) and
// re-parses every static PowerShell-dialect nested script so a payload can
// never hide an unsafe leaf on re-parse.
func FuzzRev5Inv(f *testing.F) {
	for _, s := range invariantSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51} {
			sc, _ := Parse(src, Options{Dialect: d})
			assertStaticLeafSafe(t, sc, src, d, 0)
		}
	})
}
