// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import "testing"

func TestLoopWriterReachesStateReadsTheTargetNotTheList(t *testing.T) {
	home, cwd := "/h/people/alice", "/h/people/alice/work"
	state := "/h/people/$u/.defenseclaw/config.yaml"
	rows := []struct {
		name, command string
		want          bool
	}{
		{"unread-list-copy", `for u in $(ls /h/people); do cp a.txt ` + state + `; done`, true},
		{"login-after-source", `. /dev/null; for u in $USER; do cp a.txt ` + state + `; done`, true},
		{"login-after-source-name", `source /dev/null; for u in $USER; do sed -i s/a/b/ ` + state + `; done`, true},
		{"redirect", `. /dev/null; for u in $USER; do printf x > ` + state + `; done`, true},
		{"append", `. /dev/null; for u in $USER; do printf x >> ` + state + `; done`, true},
		{"tee", `. /dev/null; for u in $USER; do printf x | tee ` + state + `; done`, true},
		{"install", `. /dev/null; for u in $USER; do install a.txt ` + state + `; done`, true},
		{"perl-in-place", `. /dev/null; for u in $USER; do perl -pi -e 1 ` + state + `; done`, true},
		{"assigned-then-sourced", `d=bob; . /dev/null; for u in $USER; do cp a.txt /h/people/$d/$u/.defenseclaw/hooks/x; done`, false},
		{"tree-entry", `. /dev/null; for u in $USER; do cp a.txt /h/people/$u/.defenseclaw/hooks/x.sh; done`, true},
		{"relative-after-cd", `cd /h/people; for u in $(ls); do cp a.txt $u/.defenseclaw/config.yaml; done`, true},
		{"home-spelled", `for f in $(ls); do cp a.txt ~/.defenseclaw/$f; done`, true},
		{"nested-loop", `for a in x; do for u in $(ls); do cp a.txt /h/people/$u/.defenseclaw/config.yaml; done; done`, true},
		{"fixed-list-sibling", `. /dev/null; for u in bob carol; do cp a.txt ` + state + `; done`, false},
		{"fixed-list-active", `. /dev/null; for u in alice; do cp a.txt ` + state + `; done`, true},
		{"known-assignment", `d=bob; for u in $d; do cp a.txt ` + state + `; done`, false},
		{"ordinary-file", `. /dev/null; for u in $USER; do cp a.txt /h/people/$u/notes.yaml; done`, false},
		{"ordinary-logs", `. /dev/null; for u in $USER; do cp a.txt /h/people/$u/.defenseclaw/logs/x.log; done`, false},
		{"ordinary-suffix", `for u in $(ls); do cp a.txt /h/people/$u/.defenseclaw/config.yaml.bak; done`, false},
		{"project-local", `for u in $(ls); do cp a.txt out/$u/.defenseclaw/config.yaml; done`, false},
		{"source-operand", `for u in $(ls); do cp /h/people/alice/.defenseclaw/config.yaml out/$u.yaml; done`, false},
		{"read-only", `for u in $(ls); do cat /h/people/$u/.defenseclaw/config.yaml; done`, false},
		{"plain-sed", `for u in $(ls); do sed s/a/b/ /h/people/$u/.defenseclaw/config.yaml; done`, false},
		{"read-names-do-not-hide-the-iterator", `read -r u </dev/null; for u in $(ls); do cp a.txt ` + state + `; done`, true},
		{"printf-names-do-not-hide-the-iterator", `printf -v u x; for u in $(ls); do cp a.txt ` + state + `; done`, true},
		{"read-variable-in-an-outer-loop", `for i in 1 2; do echo x | while read -r d; do sed -i s/a/b/ /h/people/alice/$d/config.yaml; done; done`, false},
		{"mapfile-variable-in-an-outer-loop", `for i in 1 2; do mapfile -t d <<< x; cp a.txt /h/people/alice/$d/config.yaml; done`, false},
		{"function-binds-the-list-variable", `d=.defenseclaw; f() { declare -g d=ordinary; }; f; for u in $d; do sed -i s/a/b/ /h/people/alice/$u/config.yaml; done`, false},
		{"no-loop", `. /dev/null; cp a.txt /h/people/$USER/.defenseclaw/config.yaml`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := LoopWriterReachesState(row.command, cwd, home); got != row.want {
				t.Errorf("%s = %t, want %t", row.command, got, row.want)
			}
		})
	}
}
