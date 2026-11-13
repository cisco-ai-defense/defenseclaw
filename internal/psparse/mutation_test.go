// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"fmt"
	"testing"
)

func firstArgStatic(src string) (string, bool) {
	sc, _ := Parse(src, Options{})
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

// TestStaticAllowlistMutation proves the two-tier Static-value allowlist. The
// hard-unsafe runes (a backtick escape, any control rune, any non-ASCII rune:
// the value-changing / homoglyph vectors) must make a value non-static in
// every context -- single-quoted, double-quoted and bareword. The structural
// punctuation (; & | ( ) $ ...) is literal inside quotes and stays static (the
// review-4 R4-7 widening), so a quoted nested script is not made opaque; the
// un-mutated bases stay static everywhere.
func TestStaticAllowlistMutation(t *testing.T) {
	bases := []string{"Windows", "System32", "foo", "abc123", "aXbYcZ", "a.b-c_d"}
	hardUnsafe := []rune{
		'`', 0x00, 0x1b, '\t', '\n', '\r',
		'\u2018', '\u2019', '\u201c', '\u201d', '\u201a', '\u201e',
		'\u2013', '\u2014', '\u2015', '\u00a0', '\ufeff', '\u202e',
		'é', '✓', '\ufffd',
	}
	for _, b := range bases {
		for _, wrap := range []string{"%s", "'%s'", "\"%s\""} {
			if v, ok := firstArgStatic("Write-Output " + fmt.Sprintf(wrap, b)); !ok || v != b {
				t.Errorf("base %q wrap %q: (%q,%v), want static %q", b, wrap, v, ok, b)
			}
		}
		for _, r := range hardUnsafe {
			mutated := b[:len(b)/2] + string(r) + b[len(b)/2:]
			for _, wrap := range []string{"'%s'", "\"%s\""} {
				src := "Write-Output " + fmt.Sprintf(wrap, mutated)
				if v, ok := firstArgStatic(src); ok {
					t.Errorf("hard-unsafe %q (%U): static %q, want non-static", src, r, v)
				}
			}
		}
	}
	// The widening: structural punctuation inside a single-quoted string is
	// literal and must stay static, so a quoted nested script resolves (effects
	// re-parses it and re-gates its leaves) instead of going opaque.
	for _, s := range []string{
		`'Remove-Item C:\x; Get-Date'`, `'del a & del b'`, `'a|b'`, `'$x (1)'`,
	} {
		if _, ok := firstArgStatic("Write-Output " + s); !ok {
			t.Errorf("quoted structural %s: non-static, want static (R4-7 widening)", s)
		}
	}
	// A wildcard metachar expands even inside quotes, so a quoted path value
	// with * ? [ ] is non-static (review 5 R5-3).
	for _, s := range []string{`'*.tmp'`, `'[int]'`, `"/home/u/.ss[h]"`, `"/et?"`, `'a*b'`} {
		if v, ok := firstArgStatic("Remove-Item " + s); ok {
			t.Errorf("quoted wildcard %s: static %q, want non-static (R5-3)", s, v)
		}
	}
}
