// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import "testing"

// TestBraceExpansionBudget is rel-1-0-6 GAP-0187: the cost of a command's
// brace expansions is read from the text, before anything expands.
func TestBraceExpansionBudget(t *testing.T) {
	for _, tc := range []struct {
		command string
		over    bool
	}{
		{"echo hello > out.txt", false},
		{"mkdir -p src/{a,b,c}/{x,y}", false},
		{"cp config.yaml{,.bak}", false},
		{"echo {1..100}", false},
		{"echo {a..z}{a..z}", false},
		{"echo {1..60000}", false},
		{"echo ${HOME}/{a,b}", false},
		{"echo '{1..100000000}'", false},
		{`echo "{1..100000000}"`, false},
		{`echo \{1..100000000}`, false},
		{"{ echo a; echo b; } > f", false},
		{"awk '{print $1}' f", false},
		{"Write-Output a; { Remove-Item -Recurse -Force C:\\", false},
		{"echo a\\", false},
		{"echo {1..65537}", true},
		{"echo {1..100000}", true},
		{"echo {1..100000000} > out.txt", true},
		{"echo {1..3000}{1..3000} > out.txt", true},
		{"echo {1..40}{1..40}{1..40}{1..40}{1..40} > out.txt", true},
		{"echo {a,b}{1..20000}{x,y}", true},
		{"echo {{1..300},{1..300}}{1..300}", true},
		{"echo {1..100000000..1}", true},
		{"echo {-50000..50000}", true},
		{"touch f{1..1000}; echo {1..1000}{1..100}", true},
	} {
		if got := BraceExpansionTooLarge(tc.command); got != tc.over {
			t.Errorf("BraceExpansionTooLarge(%q) = %v, want %v", tc.command, got, tc.over)
		}
		if got := TooDeep(tc.command); got != tc.over {
			t.Errorf("TooDeep(%q) = %v, want %v", tc.command, got, tc.over)
		}
	}
	// A short word repeated past the byte bound is over it too.
	long := "echo x" + string(make([]byte, 0)) + "{1..60000}" + string(repeat('y', 100))
	if !BraceExpansionTooLarge(long) {
		t.Error("60000 fields of a 116-byte word are not over the byte bound")
	}
}

func repeat(c byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = c
	}
	return out
}
