// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestGrepGlobMatchIsFnmatch: GNU fnmatch's bracket rules (substrate-1:GAP-0912).
func TestGrepGlobMatchIsFnmatch(t *testing.T) {
	for _, row := range []struct {
		glob, name   string
		match, valid bool
	}{
		{"[!.]*", "credentials", true, true},
		{"[!.]*", ".aws", false, true},
		{"[^.]*", "credentials", true, true},
		{"[]c]*", "credentials", true, true},
		{"[]c]*", "]x", true, true},
		{"[!]c]*", "credentials", false, true},
		{"[-a]x", "-x", true, true},
		{"[a-]x", "-x", true, true},
		{"[a-c]x", "bx", true, true},
		{"[abc", "[abc", true, true},
		{"[abc", "a", false, true},
		{`a\`, `a\`, true, true},
		{`\*`, "*", true, true},
		{`\*`, "a", false, true},
		{"*.go", "main.go", true, true},
		{"*", ".aws", true, true},
		{"[[:alpha:]]*", "credentials", false, false},
		{"[[=a=]]", "a", false, false},
	} {
		match, valid := grepGlobMatch(row.glob, row.name)
		if match != row.match || valid != row.valid {
			t.Errorf("grepGlobMatch(%q, %q) = %v, %v; want %v, %v", row.glob, row.name, match, valid, row.match, row.valid)
		}
	}
}
