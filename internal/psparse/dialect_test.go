package psparse

import "testing"

// TestDialectEscapes checks the Static value allowlist's dialect behaviour:
// any backtick escape (`e, `n, `u{hex}, a bare backtick) or brace makes a name
// or argument non-static in EVERY dialect, so an obfuscated token can never
// resolve to a trusted literal and the 5.1-vs-7 ambiguity can never yield a
// wrong static value. The AST .Static flag still tracks node kind (see
// projection); only the trusted value (LiteralString) is gated here.
func TestDialectEscapes(t *testing.T) {
	bt := func(s string) string { // § -> backtick
		r := []rune(s)
		for i, c := range r {
			if c == '§' {
				r[i] = '`'
			}
		}
		return string(r)
	}
	firstName := func(src string, d Dialect) (string, bool) {
		sc, _ := Parse(src, Options{Dialect: d})
		var name string
		var ok bool
		WalkCommands(sc, func(c *Command) {
			if name == "" && !ok {
				name, ok = LiteralString(c.Name)
			}
		})
		return name, ok
	}
	firstArg := func(src string, d Dialect) (string, bool) {
		sc, _ := Parse(src, Options{Dialect: d})
		var v string
		var ok bool
		done := false
		WalkCommands(sc, func(c *Command) {
			if done {
				return
			}
			for _, el := range c.Elements {
				if a, aok := el.(*Arg); aok {
					v, ok = LiteralString(a.Value)
					done = true
					return
				}
			}
		})
		return v, ok
	}

	names := []string{`i§ex x`, `§u{72}m x`, `Remov§e-Item C:\x`, `po§wershell -c x`}
	args := []string{`Write-Output a§eb`, `Write-Output a§nb`, `Write-Output a§u{41}b`}
	for _, d := range []Dialect{DialectWindowsPS51, DialectPwsh7, DialectUnknown} {
		for _, s := range names {
			if n, ok := firstName(bt(s), d); ok {
				t.Errorf("dialect %d name %q = (%q,true), want non-static (ps_unsafe_literal)", d, s, n)
			}
		}
		for _, s := range args {
			if v, ok := firstArg(bt(s), d); ok {
				t.Errorf("dialect %d arg %q = (%q,true), want non-static (ps_unsafe_literal)", d, s, v)
			}
		}
	}

	// A plain, un-escaped name/argument stays static in every dialect.
	for _, d := range []Dialect{DialectWindowsPS51, DialectPwsh7, DialectUnknown} {
		if n, ok := firstName(`Remove-Item C:\x`, d); !ok || n != "Remove-Item" {
			t.Errorf("dialect %d plain name = (%q,%v), want Remove-Item static", d, n, ok)
		}
	}
}
