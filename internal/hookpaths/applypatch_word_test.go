// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A program name inside a file name is no call (rel-1-0-10:GAP-0018).
func TestPatchProgramWordCountSkipsFileNames(t *testing.T) {
	for _, test := range []struct {
		line string
		want int
	}{
		{"cat internal/hookpaths/applypatch.go && ls", 0},
		{"cat apply_patch.md; cat x", 0},
		{"git diff -- my-apply-patch.txt | head", 0},
		{"cat a && apply_patch", 1},
		{"cat a && /usr/bin/apply_patch", 1},
		{"cat a && apply_patch.exe", 1},
		{"apply_patch; applypatch", 2},
	} {
		if got := patchProgramWordCount(test.line); got != test.want {
			t.Errorf("%q: %d, want %d", test.line, got, test.want)
		}
	}
}
