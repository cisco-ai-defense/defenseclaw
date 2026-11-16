// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// TestCommandMayDotglobReadsSettingsAndQualifiers pins the commands that may
// let a glob match a leading dot (a dotglob, globdots, GLOBIGNORE or BASH_ENV
// setting, or a (D) qualifier) and the commands that may not, whatever their
// size: the check reads the command with substring checks before the
// qualifier expression, so a large benign body must stay unchanged.
func TestCommandMayDotglobReadsSettingsAndQualifiers(t *testing.T) {
	filler := strings.Repeat("plain text with no glob settings\n", 4<<10)
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"shopt dotglob", "shopt -s dotglob; cat *", true},
		{"upper case setting", "SHOPT -S DOTGLOB", true},
		{"zsh GLOB_DOTS", "setopt GLOB_DOTS; ls *", true},
		{"underscored globdots", "setopt glob_dots", true},
		{"GLOBIGNORE", "GLOBIGNORE=x ls *", true},
		{"BASH_ENV", "BASH_ENV=/tmp/x bash -c true", true},
		{"star qualifier", "ls *(D)", true},
		{"question qualifier", "ls ?(ND)", true},
		{"bracket qualifier", "ls [a-z](D)", true},
		{"qualifier without D", "ls *(N)", false},
		{"parenthesis after a letter", "echo foo(D)", false},
		{"plain command", "cat README.md", false},
		{"large benign body", "cat <<EOF\n" + filler + "EOF\n", false},
		{"large body then setting", "cat <<EOF\n" + filler + "EOF\nshopt -s dotglob\n", true},
		{"large body then qualifier", "cat <<EOF\n" + filler + "EOF\nls *(D)\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := actionCommandMayDotglob(tc.command); got != tc.want {
				t.Fatalf("actionCommandMayDotglob = %t, want %t", got, tc.want)
			}
		})
	}
}
