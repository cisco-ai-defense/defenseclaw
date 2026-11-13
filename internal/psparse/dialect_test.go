package psparse

import "testing"

// TestDialectEscapes checks that `e and `u{hex} are PS 6/7 escapes only: under
// Windows PowerShell 5.1 they are literal (so `ex decodes to "iex"), and under
// an unknown dialect a value that would decode differently is non-static.
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

	// `ex as a command name: PS7 -> i<ESC>x, 5.1 -> iex, unknown -> dynamic.
	if n, ok := firstName(bt(`i§ex x`), DialectWindowsPS51); !ok || n != "iex" {
		t.Errorf("5.1 i`ex name = (%q,%v), want (\"iex\",true)", n, ok)
	}
	if n, ok := firstName(bt(`i§ex x`), DialectPwsh7); !ok || n != "i\x1bx" {
		t.Errorf("pwsh7 i`ex name = (%q,%v), want i<ESC>x", n, ok)
	}
	if _, ok := firstName(bt(`i§ex x`), DialectUnknown); ok {
		t.Errorf("unknown-dialect i`ex name must be non-static")
	}

	// `u{72}m name: PS7 -> rm, 5.1 -> u{72}m, unknown -> dynamic.
	if n, ok := firstName(bt(`§u{72}m x`), DialectWindowsPS51); !ok || n != "u{72}m" {
		t.Errorf("5.1 `u{72}m = (%q,%v), want u{72}m", n, ok)
	}
	if n, ok := firstName(bt(`§u{72}m x`), DialectPwsh7); !ok || n != "rm" {
		t.Errorf("pwsh7 `u{72}m = (%q,%v), want rm", n, ok)
	}
	if _, ok := firstName(bt(`§u{72}m x`), DialectUnknown); ok {
		t.Errorf("unknown-dialect `u{72}m must be non-static")
	}

	// `e in an argument: PS7 -> ESC, 5.1 -> e, unknown -> dynamic.
	if v, ok := firstArg(bt(`Write-Output a§eb`), DialectWindowsPS51); !ok || v != "aeb" {
		t.Errorf("5.1 a`eb = (%q,%v), want aeb", v, ok)
	}
	if v, ok := firstArg(bt(`Write-Output a§eb`), DialectPwsh7); !ok || v != "a\x1bb" {
		t.Errorf("pwsh7 a`eb = (%q,%v), want a<ESC>b", v, ok)
	}
	if _, ok := firstArg(bt(`Write-Output a§eb`), DialectUnknown); ok {
		t.Errorf("unknown-dialect a`eb must be non-static")
	}

	// a non-divergent escape (`n) is static in every dialect.
	for _, d := range []Dialect{DialectPwsh7, DialectWindowsPS51, DialectUnknown} {
		if v, ok := firstArg(bt(`Write-Output a§nb`), d); !ok || v != "a\nb" {
			t.Errorf("dialect %d a`nb = (%q,%v), want a\\nb static", d, v, ok)
		}
	}
}
