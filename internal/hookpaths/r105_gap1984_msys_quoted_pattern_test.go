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
}
