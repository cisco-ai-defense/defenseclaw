// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestStepUpSpellingKeepsADotDotNameRaw: a name with a dot-dot segment at any
// place, a leading one included, is spelled raw from the working directory (the
// links before the segment decide the directory it leaves), and every other
// name has none. clientOperandKey is the same spelling for such names.
func TestStepUpSpellingKeepsADotDotNameRaw(t *testing.T) {
	rows := []struct {
		name, dir, want string
		steps           bool
	}{
		{"lnk/../ld.so.preload", "/home/u/proj", "/home/u/proj/lnk/../ld.so.preload", true},
		{"../ld.so.preload", "/home/u/proj/lnk", "/home/u/proj/lnk/../ld.so.preload", true},
		{"..", "/home/u/proj/lnk", "/home/u/proj/lnk/..", true},
		{"lnk/..", "/home/u/proj", "/home/u/proj/lnk/..", true},
		{"/home/u/proj/lnk/../x", "/home/u/proj", "/home/u/proj/lnk/../x", true},
		{"../x", "", "", false},
		{"..x/y", "/home/u/proj", "", false},
		{"x..y", "/home/u/proj", "", false},
		{"sub/notes.txt", "/home/u/proj", "", false},
		{"", "/home/u/proj", "", false},
	}
	for _, row := range rows {
		got, steps := StepUpSpelling(row.name, row.dir)
		if got != row.want || steps != row.steps {
			t.Errorf("StepUpSpelling(%q, %q) = %q, %t; want %q, %t", row.name, row.dir, got, steps, row.want, row.steps)
		}
		if row.steps && clientOperandKey(row.name, row.dir) != row.want {
			t.Errorf("clientOperandKey(%q, %q) = %q, want the raw spelling %q", row.name, row.dir, clientOperandKey(row.name, row.dir), row.want)
		}
	}
	if got := clientOperandKey("sub/./notes.txt", "/home/u/proj"); got != "/home/u/proj/sub/notes.txt" {
		t.Errorf("a name without a dot-dot segment is cleaned, got %q", got)
	}
}
