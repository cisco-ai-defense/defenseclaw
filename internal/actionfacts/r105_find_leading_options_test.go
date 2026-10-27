// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// GAP-2135: the options before find's starting points are skipped, and a
// BSD -f path is a starting point.
func TestR105GAP2135FindLeadingOptions(t *testing.T) {
	for _, tc := range []struct {
		argv  []string
		paths []string
	}{
		{[]string{"find", "-D", "tree", "/h/.defenseclaw", "-delete"}, []string{"/h/.defenseclaw"}},
		{[]string{"find", "-O3", "/h/.defenseclaw", "-delete"}, []string{"/h/.defenseclaw"}},
		{[]string{"find", "-L", "-x", "-E", "/a", "/b", "-name", "x"}, []string{"/a", "/b"}},
		{[]string{"find", "-xs", "/a"}, []string{"/a"}},
		{[]string{"find", "-f", "/a", "-f", "/b", "-print"}, []string{"/a", "/b"}},
		{[]string{"find", "-xf", "/a"}, []string{"/a"}},
		{[]string{"find", "-q", "/a"}, nil},
		{[]string{"find", "/a", "-x", "/b"}, []string{"/a"}},
		{[]string{"find", "--", "-a"}, nil},
	} {
		if got := findStartingPaths(tc.argv); !slices.Equal(got, tc.paths) {
			t.Errorf("%q: starting paths %q, want %q", tc.argv, got, tc.paths)
		}
	}
}
