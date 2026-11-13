// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// TestStaticAllowlistMutation is the review-3 item-1 mutation test: inserting
// any rune outside the Static-value allowlist into an otherwise-static argument
// must make LiteralString report it non-static (ps_unsafe_literal), while the
// un-mutated bases stay static. It proves the allowlist closes the obfuscation
// class, not just the specific shapes the differential corpus happens to carry.
func TestStaticAllowlistMutation(t *testing.T) {
	firstArg := func(src string) (string, bool) {
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
	bases := []string{"Windows", "System32", "foo", "abc123", "aXbYcZ", "a.b-c_d"}
	// every rune here is outside the allowlist and must force non-static
	unsafe := []rune{
		'`', '[', ']', '{', '}', '$', '(', ')', ';', '|', '&', '*', '?',
		'<', '>', '#', '^', '!', 0x00, 0x1b, '\t', '\n', '\r',
		'‘', '’', '“', '”', '–', '—', 'é', '✓',
	}
	for _, b := range bases {
		// control: the un-mutated base resolves static (single-quoted literal)
		if v, ok := firstArg("Write-Output '" + b + "'"); !ok || v != b {
			t.Errorf("base %q: got (%q,%v), want static %q", b, v, ok, b)
		}
		for _, r := range unsafe {
			mutated := b[:len(b)/2] + string(r) + b[len(b)/2:]
			// a single-quoted string keeps every rune literal, so only the
			// source allowlist decides staticness.
			src := "Write-Output '" + mutated + "'"
			if v, ok := firstArg(src); ok {
				t.Errorf("mutation %q (rune %U): resolved static %q, want non-static", src, r, v)
			}
		}
	}
}
