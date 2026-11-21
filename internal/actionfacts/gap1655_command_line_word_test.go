// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestGAP1655CommandLineQuotedWord: one double-quoted word of a child command
// line is taken apart by the CommandLineToArgvW rules; anything else is not
// one quoted word (rel-1-0-10:GAP-1655).
func TestGAP1655CommandLineQuotedWord(t *testing.T) {
	for _, c := range []struct {
		text, want string
		ok         bool
	}{
		{`"a b"`, `a b`, true},
		{`"a \"b\" c"`, `a "b" c`, true},
		{`"C:\x\y"`, `C:\x\y`, true},
		{`"C:\work\\"`, `C:\work\`, true},
		{`"a\\\"b"`, `a\"b`, true},
		{`""`, ``, true},
		{`"a" "b"`, ``, false},
		{`"a""b"`, ``, false},
		{`"a\"`, ``, false},
		{`"a`, ``, false},
		{`a"`, ``, false},
		{`a`, ``, false},
	} {
		got, ok := commandLineQuotedWord(c.text)
		if got != c.want && ok || ok != c.ok {
			t.Errorf("%s: %q %v, want %q %v", c.text, got, ok, c.want, c.ok)
		}
	}
	if got := commandLineBody(`""`); got != `""` {
		t.Errorf(`empty quoted body: %q, want "" as written`, got)
	}
}
