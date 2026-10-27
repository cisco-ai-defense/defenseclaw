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
		// getopt takes an attached -f path (pod check7).
		{[]string{"find", "-f/a", "-delete"}, []string{"/a"}},
		{[]string{"find", "-xf/a", "-name", "x"}, []string{"/a"}},
		{[]string{"find", "-sf/a", "/b"}, []string{"/a", "/b"}},
		{[]string{"/usr/bin/find", "-f/a", "--", "-delete"}, []string{"/a"}},
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

// GAP-2135 (pod check7): an attached -f$HOME/... path gets the trusted home
// like a separate word, so find -delete names the state root.
func TestR105GAP2135FindAttachedHomePath(t *testing.T) {
	for _, command := range []string{
		"find -f$HOME/.defenseclaw -delete",
		"find -xf${HOME}/.defenseclaw -delete",
		"find -f/home/u/.defenseclaw -delete",
	} {
		facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/home/u/p", ActiveHome: "/home/u"})
		if !hasPathFact(facts, PathAccessDelete, "/home/u/.defenseclaw") {
			t.Errorf("%q: no delete fact for the state root: %+v (%+v)", command, facts.Paths, facts.Parse)
		}
	}
	// A tilde attached to an option is not expanded by the shell.
	facts := Analyze(Input{Tool: "Bash", Command: "find -f~/.defenseclaw -delete", CWD: "/home/u/p", ActiveHome: "/home/u"})
	if hasPathFact(facts, PathAccessDelete, "/home/u/.defenseclaw") {
		t.Errorf("-f~/: the tilde is literal, got %+v", facts.Paths)
	}
}

// GAP-2122 (pod check7): a find that hands what it finds to a program that
// may change it gives its starting points a written path fact, with the
// trusted home resolved, while readers and mode changes add none.
func TestR105GAP2122FindHandsEntriesToWriter(t *testing.T) {
	for _, tc := range []struct {
		command string
		write   bool
	}{
		{`find ~/.defenseclaw/hooks -exec sh -c 'rm -f "$1"' _ {} \;`, true},
		{"find ~/.defenseclaw/hooks -type f -exec truncate -s 0 {} +", true},
		{"find $HOME/.defenseclaw/hooks -exec sudo rm -f {} +", true},
		{"find ~/.defenseclaw/hooks -exec env rm -f {} +", true},
		{`find ~/.defenseclaw/hooks -type f -exec cp /dev/null {} \;`, true},
		{"find ~/.defenseclaw/hooks -type f -exec ls -l {} +", false},
		{"find ~/.defenseclaw/hooks -type f -exec sha256sum {} +", false},
		{"find ~/.defenseclaw/hooks -exec chmod 700 {} +", false},
	} {
		facts := Analyze(Input{Tool: "Bash", Command: tc.command, CWD: "/home/u/p", ActiveHome: "/home/u"})
		if got := hasPathFact(facts, PathAccessWrite, "/home/u/.defenseclaw/hooks"); got != tc.write {
			t.Errorf("%q: written start point %t, want %t: %+v", tc.command, got, tc.write, facts.Paths)
		}
		if !hasPathFact(facts, PathAccessRead, "/home/u/.defenseclaw/hooks") {
			t.Errorf("%q: the home start point is not resolved: %+v (%+v)", tc.command, facts.Paths, facts.Parse)
		}
	}
	// find piped into xargs keeps its resolved starting point.
	facts := Analyze(Input{Tool: "Bash", Command: "find ~/.defenseclaw/hooks -type f | xargs rm -f", CWD: "/home/u/p", ActiveHome: "/home/u"})
	if !hasPathFact(facts, PathAccessRead, "/home/u/.defenseclaw/hooks") {
		t.Errorf("find | xargs: the home start point is not resolved: %+v (%+v)", facts.Paths, facts.Parse)
	}
}

func hasPathFact(facts Facts, access PathAccess, resolved string) bool {
	for _, path := range facts.Paths {
		if path.Access == access && path.Resolved == resolved {
			return true
		}
	}
	return false
}
