// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// TestGAP0699MoveOrExitIsCertain is substrate-1:GAP-0699: after `cd X ||
// exit` the shell goes on only in X (the exit ends it where the cd failed),
// so a later relative write is read in X alone, as after `cd X &&`. The same
// holds for a { } group that ends in exit. A return, an exit in a subshell, a pipe or the
// background, and an exit a function of the text may shadow end nothing
// here: the write keeps the reading in the folder the call started in.
func TestGAP0699MoveOrExitIsCertain(t *testing.T) {
	const cwd, home = "/work/proj", "/home/alice"
	for _, tc := range []struct {
		name, command string
		want          []string
	}{
		{"or exit", "cd /srv || exit 1; echo x > g", []string{"/srv/g"}},
		{"or exit, no status", "cd /srv || exit\necho x > g", []string{"/srv/g"}},
		{"or builtin exit", "cd /srv || builtin exit 2; echo x > g", []string{"/srv/g"}},
		{"or a group that ends in exit", "cd /srv || { echo no >&2; exit 1; }; echo x > g", []string{"/srv/g"}},
		{"two steps or exit", "cd /srv && cd app || exit 1; echo x > g", []string{"/srv/app/g"}},
		{"pushd or exit", "pushd /srv >/dev/null || exit 1; echo x > g", []string{"/srv/g"}},
		// Not an end of the shell: the write keeps the hook folder's reading.
		{"or return outside a body", "cd /srv || return 1; echo x > g", []string{"/srv/g", "/work/proj/g"}},
		{"or exit in a subshell", "cd /srv || (exit 1); echo x > g", []string{"/srv/g", "/work/proj/g"}},
		{"or exit in a pipe", "cd /srv || exit 1 | cat; echo x > g", []string{"/srv/g", "/work/proj/g"}},
		{"or a group that goes on", "cd /srv || { exit 1; echo no; }; echo x > g", []string{"/srv/g", "/work/proj/g"}},
		{"exit shadowed", "exit() { :; }; cd /srv || exit 1; echo x > g", []string{"/srv/g", "/work/proj/g"}},
		{"semicolon", "cd /srv; echo x > g", []string{"/srv/g", "/work/proj/g"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home, DialectHint: DialectPOSIX})
			var got []string
			for _, candidate := range facts.Paths {
				if (candidate.Access == PathAccessWrite || candidate.Access == PathAccessAppend) && candidate.Value == "g" &&
					!slices.Contains(got, candidate.Resolved) {
					got = append(got, candidate.Resolved)
				}
			}
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("%q: resolved writes %q, want %q", tc.command, got, want)
			}
		})
	}
}
