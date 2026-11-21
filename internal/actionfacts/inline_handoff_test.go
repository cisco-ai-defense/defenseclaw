// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0365: the one rule for the words a runner hands an inline
// interpreter child.
func TestInlineCodeHandedWords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		argv  []string
		from  int
		fed   bool
		words []string
	}{
		{"python direct", []string{"python3", "-c", "CODE", "/h/c"}, 3, false, []string{"/h/c"}},
		{"python options", []string{"python3", "-I", "-X", "dev", "-c", "CODE", "/h/c", "/h/d"}, 6, false, []string{"/h/c", "/h/d"}},
		{"python cluster", []string{"python3", "-Ic", "CODE", "/h/c"}, 3, false, []string{"/h/c"}},
		{"absolute and versioned", []string{"/usr/bin/python3.12", "-c", "CODE", "/h/c"}, 3, false, []string{"/h/c"}},
		{"sudo", []string{"sudo", "-n", "python3", "-c", "CODE", "/h/c"}, 5, false, []string{"/h/c"}},
		{"env nice timeout", []string{"env", "A=1", "nice", "-n", "5", "timeout", "5", "node", "-e", "CODE", "/h/c"}, 10, false, []string{"/h/c"}},
		{"node print", []string{"node", "-p", "CODE", "/h/c"}, 3, false, []string{"/h/c"}},
		{"python fused code", []string{"python3", "-c\"import sys\"", "/h/c"}, 2, false, []string{"/h/c"}},
		{"python flags then fused code", []string{"python3", "-Bc import sys", "/h/c"}, 2, false, []string{"/h/c"}},
		{"ruby cluster", []string{"ruby", "-ne", "CODE", "/h/c"}, 3, false, []string{"/h/c"}},
		{"perl reads", []string{"perl", "-ne", "print", "/h/c"}, -1, false, nil},
		{"perl code", []string{"perl", "-e", "CODE", "/h/c"}, -1, false, nil},
		{"ruby", []string{"ruby", "-e", "CODE", "/h/c"}, 3, false, []string{"/h/c"}},
		{"php", []string{"php", "-r", "CODE", "/h/c"}, 3, false, []string{"/h/c"}},
		{"xargs echo", []string{"xargs", "-n1", "python3", "-c", "CODE"}, 5, true, nil},
		{"xargs -I", []string{"xargs", "-I", "{}", "python3", "-c", "CODE", "{}"}, 6, true, nil},
		{"xargs -0 sudo", []string{"xargs", "-0", "sudo", "python3", "-c", "CODE"}, 6, true, nil},
		{"parallel inputs", []string{"parallel", "python3", "-c", "CODE", ":::", "/h/c"}, 4, true, []string{":::", "/h/c"}},
		{"text is no path", []string{"python3", "-c", "CODE", "two words", "a;b", "$x", "-v", "'q'"}, 3, false, nil},
		{"script, not code", []string{"python3", "tool.py", "-c", "x", "/h/c"}, -1, false, nil},
		{"module", []string{"python3", "-m", "tool", "-c", "x", "/h/c"}, -1, false, nil},
		{"lua takes a script", []string{"lua", "-e", "CODE", "/h/c"}, -1, false, nil},
		{"no code word", []string{"python3", "-c"}, -1, false, nil},
		{"plain program", []string{"cat", "/h/c"}, -1, false, nil},
		{"xargs plain program", []string{"xargs", "cat"}, -1, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			from, fed := InlineCodeHandedFrom(tc.argv)
			if from != tc.from || fed != tc.fed {
				t.Fatalf("InlineCodeHandedFrom(%q) = %d, %t; want %d, %t", tc.argv, from, fed, tc.from, tc.fed)
			}
			if got := InlineCodeHandedWords(tc.argv); !slices.Equal(got, tc.words) {
				t.Fatalf("InlineCodeHandedWords(%q) = %q; want %q", tc.argv, got, tc.words)
			}
		})
	}
}
