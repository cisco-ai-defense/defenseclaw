// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TestBodyStatementsAreReadInEveryFolderTheirCallMayRunIn: the walk of the
// split moves its folder at every cd as if it ran, so a statement it reads in
// a nested body (eval, sh -c, bash -c) or a function body is also read in
// each folder the working-folder tracking gives its call: after
// `cd A || cd B && <body>` the body runs in A or in B, never only in the one
// folder the walk ended in (rel-1-0-10:GAP-1144, GAP-0183). A subshell moves
// nothing outside, so a body after it runs where the call started. A call
// of a function whose body moves leaves the shell where that body may.
func TestBodyStatementsAreReadInEveryFolderTheirCallMayRunIn(t *testing.T) {
	const cwd, home = "/home/u/project", "/home/u"
	write := "echo m > $x"
	cases := []struct {
		name, command string
		want, never   []string
	}{
		{"eval in || tail", `cd /srv/a || cd /srv/b && eval 'x=notes.txt; echo m > $x'`, []string{"/srv/a", "/srv/b"}, []string{cwd}},
		{"sh -c in || tail", `cd /srv/a || cd /srv/b && sh -c 'x=notes.txt; echo m > $x'`, []string{"/srv/a", "/srv/b"}, []string{cwd}},
		{"eval after failed cd", `cd /srv/missing || cd /srv/a && eval 'x=notes.txt; echo m > $x'`, []string{"/srv/a", "/srv/missing"}, []string{cwd}},
		{"eval after ;", `cd /srv/a || cd /srv/b; eval 'x=notes.txt; echo m > $x'`, []string{"/srv/a", "/srv/b", cwd}, nil},
		{"group then eval", `{ cd /srv/a || cd /srv/b; } && eval 'x=notes.txt; echo m > $x'`, []string{"/srv/a", "/srv/b"}, []string{cwd}},
		{"subshell then eval", `(cd /srv/a || cd /srv/b) && eval 'x=notes.txt; echo m > $x'`, []string{cwd}, []string{"/srv/a", "/srv/b"}},
		{"function defined in tail", `cd /srv/a || cd /srv/b && f() { x=notes.txt; echo m > $x; }; f`, []string{"/srv/a", "/srv/b"}, nil},
		{"function called in tail", `f() { x=notes.txt; echo m > $x; }; cd /srv/a || cd /srv/b && f`, []string{"/srv/a", "/srv/b"}, []string{cwd}},
		{"function called in subshell tail", `f() { x=notes.txt; echo m > $x; }; (cd /srv/a || cd /srv/b); f`, []string{cwd}, []string{"/srv/a", "/srv/b"}},
		{"function body moves", `f() { cd sub; x=notes.txt; echo m > $x; }; cd /srv/a || cd /srv/b && f`, []string{"/srv/a/sub", "/srv/b/sub"}, nil},
		{"mover function then eval", `f() { cd /srv/a || cd /srv/b; }; f; eval 'x=notes.txt; echo m > $x'`, []string{"/srv/a", "/srv/b", cwd}, nil},
		{"mover function in && head", `f() { cd /srv/a || cd /srv/b; }; f && sh -c 'x=notes.txt; echo m > $x'`, []string{"/srv/a", "/srv/b"}, []string{cwd}},
		{"mover function in subshell", `f() { (cd /srv/a || cd /srv/b); }; f && eval 'x=notes.txt; echo m > $x'`, []string{cwd}, []string{"/srv/a", "/srv/b"}},
		{"function calls function", `g() { x=notes.txt; echo m > $x; }; f() { g; }; cd /srv/a || cd /srv/b && f`, []string{"/srv/a", "/srv/b"}, []string{cwd}},
	}
	for _, c := range cases {
		args, _ := json.Marshal(map[string]any{"command": c.command})
		input := Input{Tool: "Bash", Args: args, Command: c.command, CWD: cwd, ActiveHome: home}
		var folders []string
		for _, simple := range SimpleCommands(input, Analyze(input)) {
			if simple.EvaluationFailure != "" {
				t.Errorf("%s: evaluation failure %q", c.name, simple.EvaluationFailure)
			}
			if strings.Contains(simple.Text, "notes.txt") && !strings.Contains(simple.Text, write) && !strings.Contains(simple.Text, "x=") {
				folders = append(folders, simple.CWD)
			}
		}
		for _, want := range c.want {
			if !slices.Contains(folders, want) {
				t.Errorf("%s: the write is not read in %s (read in %q)", c.name, want, folders)
			}
		}
		for _, never := range c.never {
			if slices.Contains(folders, never) {
				t.Errorf("%s: the write is read in %s, where it never runs (read in %q)", c.name, never, folders)
			}
		}
	}
}
