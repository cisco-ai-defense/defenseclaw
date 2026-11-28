// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1155 (CHK-SAFEPERL): actionCdSearchMayApply keeps a match once found;
// a later word in the command never clears it.
func TestGAP1155CdSearchMayApplyKeepsAnEarlierMatch(t *testing.T) {
	search := "CD" + "PATH"
	tail := "; cd w3 && echo done"
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"export_then_words", "export " + search + "=/w" + tail, true},
		{"assignment_then_words", search + "=/w" + tail, true},
		{"prefix_then_nested_shell", search + "=/w sh -c \"cd w3 && echo done\"", true},
		{"zsh_cdpath_then_words", "cd" + "path=(/w)" + tail, true},
		{"cdable_vars_then_words", "shopt -s cdable" + "_vars; v=/w" + tail, true},
		{"indirect_then_words", "echo ${!n}" + tail, true},
		{"arithmetic_then_words", "(( n = 1 ))" + tail, true},
		{"plain", "cd w3 && echo done", false},
		{"other_prefix_nested_shell", "X=1 sh -c \"cd w3 && echo done\"", false},
	} {
		file, ok := parseShell(tc.command)
		if !ok {
			t.Fatalf("%s: parse failed", tc.name)
		}
		if got := actionCdSearchMayApply(file, "/h"); got != tc.want {
			t.Errorf("%s: actionCdSearchMayApply = %v, want %v (GAP-1155)", tc.name, got, tc.want)
		}
	}
}
