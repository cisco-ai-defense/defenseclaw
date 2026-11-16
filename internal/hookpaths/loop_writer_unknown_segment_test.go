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
			if got := LoopWriterReachesState(row.command, cwd, home, false); got != row.want {
				t.Errorf("%s = %t, want %t", row.command, got, row.want)
			}
		})
	}
}

func TestLoopWriterKnownValuesAndDeadCode(t *testing.T) {
	home, cwd := "/h/people/alice", "/h/people/alice/work"
	state := "/h/people/$u/.defenseclaw/config.yaml"
	loop := func(list, body string) string { return "for u in " + list + "; do " + body + "; done" }
	copyState := "cp a.txt " + state
	rows := []struct {
		name, command string
		loose, strict bool
	}{
		{"empty-assignment-list", "list=; " + loop("$list", copyState), false, false},
		{"empty-assignment-list-editor", "list=; " + loop("$list", "sed -i s/a/b/ "+state), false, false},
		{"list-with-no-word", loop("", copyState), false, false},
		{"quoted-empty-word-is-one-ordinary-path", loop(`""`, copyState), false, false},
		{"quoted-empty-variable-is-one-ordinary-path", "list=; " + loop(`"$list"`, copyState), false, false},
		{"empty-word-beside-the-active-login", "list=; " + loop("$list alice", copyState), true, true},
		{"no-list-reads-the-positional-parameters", "for u; do " + copyState + "; done", true, true},
		{"home-assignment-moves-the-tilde", "HOME=/h/project; " + loop("$USER", "cp a.txt ~/.defenseclaw/config.yaml"), false, false},
		{"home-unchanged-tilde-is-active-state", loop("$USER", "cp a.txt ~/.defenseclaw/config.yaml"), true, true},
		{"home-assignment-to-active-home", "HOME=" + home + "; " + loop("$USER", "cp a.txt ~/.defenseclaw/config.yaml"), true, true},
		{"uncalled-function", "f() { " + loop("$USER", copyState) + "; }; :", false, true},
		{"called-function", "f() { " + loop("$USER", copyState) + "; }; f", true, true},
		{"false-branch", "if false; then " + loop("$USER", copyState) + "; fi", false, true},
		{"true-branch", "if true; then " + loop("$USER", copyState) + "; fi", true, true},
		{"else-of-false-branch", "if false; then :; else " + loop("$USER", copyState) + "; fi", true, true},
		{"else-of-true-branch", "if true; then :; else " + loop("$USER", copyState) + "; fi", false, true},
		{"unknown-condition", "if [ -n \"$X\" ]; then " + loop("$USER", copyState) + "; fi", true, true},
		{"false-and", "false && " + loop("$USER", copyState), false, true},
		{"true-or", "true || " + loop("$USER", copyState), false, true},
		{"true-and", "true && " + loop("$USER", copyState), true, true},
		{"while-false", "while false; do " + loop("$USER", copyState) + "; done", false, true},
		{"tree-root-of-any-user", loop("$(ls)", "cp a.txt /h/people/$u/.defenseclaw/hooks"), true, true},
		{"another-tree-root", loop("$(ls)", "cp a.txt /h/people/$u/.defenseclaw/cache"), true, true},
		{"ordinary-sibling-of-the-tree-root", loop("$(ls)", "cp a.txt /h/people/$u/.defenseclaw/hooks.bak"), false, false},
		{"ordinary-logs-directory", loop("$(ls)", "cp a.txt /h/people/$u/.defenseclaw/logs"), false, false},
		{"body-assignment-moves-the-iterator", loop("$USER", "u=ordinary; "+copyState), false, false},
		{"write-before-the-body-assignment", loop("$USER", copyState+"; u=ordinary"), true, true},
		{"eval-in-the-body-keeps-a-fixed-name", loop("ordinary", "eval :; "+copyState), false, false},
		{"eval-in-the-body-keeps-the-login", loop("$USER", "eval :; "+copyState), true, true},
		{"body-assignment-to-an-unknown-value", loop("$USER", "u=$(ls); "+copyState), true, true},
	}
	for _, row := range rows {
		for _, strict := range []bool{false, true} {
			want := row.loose
			if strict {
				want = row.strict
			}
			if got := LoopWriterReachesState(row.command, cwd, home, strict); got != want {
				t.Errorf("%s strict=%t: %s = %t, want %t", row.name, strict, row.command, got, want)
			}
		}
	}
}
