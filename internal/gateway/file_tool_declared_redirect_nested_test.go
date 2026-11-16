//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// TestRVGXARGNestedDeclaredLink follows a known link target through each
// shell statement body. A later assignment to an ordinary file supersedes it.
func TestRVGXARGNestedDeclaredLink(t *testing.T) {
	home, project := rvgxSetup(t)
	link := filepath.Join(project, "stlink")
	ordinary := filepath.Join(project, "notes.txt")
	type form struct {
		name, command string
		block         bool
	}
	forms := []form{
		{"and", `export F=%s && printf x > "$F"`, true},
		{"and-chain", `export F=%s && true && printf x > "$F"`, true},
		{"or", `export F=%s || exit 1; printf x > "$F"`, true},
		{"leading-and", `true && export F=%s; printf x > "$F"`, true},
		{"block", `{ export F=%s; printf x > "$F"; }`, true},
		{"subshell", `(export F=%s; printf x > "$F")`, true},
		{"if", `if true; then export F=%s; printf x > "$F"; fi`, true},
		{"while", `while true; do export F=%s; printf x > "$F"; break; done`, true},
		{"for", `for n in 1; do export F=%s; printf x > "$F"; done`, true},
		{"case", `case x in x) export F=%s; printf x > "$F";; esac`, true},
		{"nested-subshell", `{ (export F=%s; printf x > "$F"); }`, true},
		{"plain-assignment", `F=%s && printf x > "$F"`, true},
		{"declare", `declare F=%s; printf x > "$F"`, true},
		{"function", `f(){ export F=%s; printf x > "$F"; }; f`, true},
		{"local", `f(){ local F=%s; printf x > "$F"; }; f`, true},
		{"function-declare", `f(){ declare F=%s; printf x > "$F"; }; f`, true},
		{"substitution", `v=$(export F=%s; printf x > "$F")`, true},
		{"reassigned-and", `export F=%s && F=%s && printf x > "$F"`, false},
		{"reassigned-block", `{ export F=%s; F=%s; printf x > "$F"; }`, false},
		{"reassigned-if", `if true; then export F=%s; F=%s; printf x > "$F"; fi`, false},
		{"reassigned-function", `f(){ local F=%s; F=%s; printf x > "$F"; }; f`, false},
		{"reassigned-case", `case x in x) export F=%s; F=%s; printf x > "$F";; esac`, false},
	}
	unknownConditions := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "[ -e /n%d ] && V%d=1; ", i, i)
		}
		return b.String()
	}
	forms = append(forms,
		form{"budget-seven-branches", `export F=%s; ` + unknownConditions(7) + `printf x > "$F"`, true},
		form{"budget-four-branches-steps", `export F=%s; ` + unknownConditions(4) + strings.Repeat(`: ; `, 40) + `printf x > "$F"`, true},
		form{"budget-three-branches-echo", `export F=%s; ` + unknownConditions(3) + strings.Repeat(`echo ok; `, 70) + `printf x > "$F"`, true},
		form{"export-existing-value", `F=%s; export F; printf x > "$F"`, true},
		form{"export-existing-value-and", `F=%s && export F && printf x > "$F"`, true},
		form{"export-n-existing-value", `F=%s; export -n F; printf x > "$F"`, true},
		form{"budget-then-benign-reassignment", `export F=%s; ` + unknownConditions(6) + `F=%s; printf x > "$F"`, false},
	)
	for _, cell := range rvgxCells {
		t.Run(cell.profile+fmt.Sprint(cell.managed), func(t *testing.T) {
			rvgxInstall(t, cell.profile)
			for i, form := range forms {
				command := fmt.Sprintf(form.command, link)
				if !form.block {
					command = fmt.Sprintf(form.command, link, ordinary)
				}
				_, action, _, body := rvgxVerdict(t, "claudecode", "Bash", map[string]any{"command": command}, cell.profile, cell.managed, home, project, fmt.Sprintf("gxarg-r3-%d", i))
				got := strings.Split(action, "/")[0]
				if form.block && got != "block" {
					t.Errorf("%s: %s, want block (%.300s)", form.name, got, body)
				} else if !form.block && got != "allow" {
					t.Errorf("%s: %s, want allow (%.300s)", form.name, got, body)
				}
			}
		})
	}
}
