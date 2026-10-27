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

// GAP-2122: an exact embedded rm/unlink/rmdir/shred makes the starting
// points delete operands, and mv {} DEST move sources; any other embedded
// command is not exact.
func TestR105GAP2122FindExactEmbeddedCommands(t *testing.T) {
	for _, tc := range []struct {
		argv           []string
		exact, deletes bool
		moveTo         []string
	}{
		{[]string{"find", "/a", "-exec", "rm", "-f", "{}", "+"}, true, true, nil},
		{[]string{"find", "/a", "-execdir", "/usr/bin/unlink", "{}", ";"}, true, true, nil},
		{[]string{"find", "/a", "-ok", "rmdir", "{}", ";", "-exec", "true", ";"}, true, true, nil},
		{[]string{"find", "/a", "-exec", "mv", "{}", "/tmp/", ";"}, true, false, []string{"/tmp/"}},
		{[]string{"find", "/a", "-name", "x"}, true, false, nil},
		{[]string{"find", "/a", "-exec", "rm", "-rf", "/etc", "{}", ";"}, false, false, nil},
		{[]string{"find", "/a", "-exec", "env", "rm", "{}", ";"}, false, false, nil},
		{[]string{"find", "/a", "-exec", "sh", "-c", "rm {}", ";"}, false, false, nil},
		{[]string{"find", "/a", "-exec", "grep", "rm", "{}", ";"}, false, false, nil},
		{[]string{"find", "/a", "-exec", "mv", "-t", "/tmp", "{}", "+"}, false, false, nil},
		{[]string{"find", "/a", "-exec", "rm", "{}"}, false, false, nil},
		{[]string{"find", "/a", "-exec", "true", "x", ";"}, false, false, nil},
	} {
		got := findExactEmbeddedCommands(tc.argv)
		if got.exact != tc.exact || got.exact && (got.deletes != tc.deletes || !slices.Equal(got.moveTo, tc.moveTo)) {
			t.Errorf("%q: embedded %+v, want exact=%t deletes=%t moveTo=%q", tc.argv, got, tc.exact, tc.deletes, tc.moveTo)
		}
	}
}
