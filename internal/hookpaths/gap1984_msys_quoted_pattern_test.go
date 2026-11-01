// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1984 (review RV4-3, regression of the GAP-1717 quoted-pattern rule):
// the MSYS tools of Git for Windows started from PowerShell receive a quoted
// word unquoted and expand it themselves, so an in-place editor pattern that
// selects the protected key file is a protected target in action mode. Only
// a printed word, a git word and the pattern argument of a search tool are
// text (GAP-1717).
func TestActionWindowsMSYSQuotedPatternStaysAPath(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, tc := range []struct {
		name, command, want string
	}{
		{"single-quoted editor pattern", `sed -i s/x/y/ 'C:\Users\u\.ssh\authorized_k*'`, "protected-target"},
		{"double-quoted editor pattern", `sed -i s/x/y/ "$HOME\.ssh\authorized_k*"`, "protected-target"},
		{"unquoted editor pattern", `sed -i s/x/y/ C:\Users\u\.ssh\authorized_k*`, "protected-target"},
		{"GAP-1717 grep pattern", `grep -rn "*** Begin Patch" .`, ""},
		{"GAP-1717 grep -e pattern", `grep -rn -e "*** Begin Patch" .`, ""},
		{"GAP-1717 rg glob pattern", `rg -n '*.md' .`, ""},
		{"GAP-1717 echo star", `echo "*"`, ""},
		{"GAP-1717 git pathspec", `git add "*"`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
	// RV5-3: from the home folder, the value of an option that takes one
	// (-A 2, -m 5, -C 3, -g '*.md') is not the search pattern; the quoted
	// pattern after it is text and selects nothing.
	for _, tc := range []struct {
		name, command, want string
	}{
		{"grep -A value", `grep -rn -A 2 "*** Begin Patch" .`, ""},
		{"grep -m value", `grep -rn -m 5 "*** Begin Patch" .`, ""},
		{"rg -C value", `rg -n -C 3 "*** Begin Patch" .`, ""},
		{"rg -g value", `rg -n -g '*.md' "*** Begin Patch" .`, ""},
		{"grep -r is no value option", `grep -r "*** Begin Patch" .`, ""},
		{"sed after a search keeps its path", `grep -rn -A 2 "x" . ; sed -i s/x/y/ 'C:\Users\u\.ssh\authorized_k*'`, "protected-target"},
	} {
		t.Run("home/"+tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, home, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}
