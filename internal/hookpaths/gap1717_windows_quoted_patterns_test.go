// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1717: on a native Windows home the target scan read a quoted pattern
// given to a native program or printed (echo "*", grep -rn "*** Begin
// Patch" .) and the *** lines of an apply_patch heredoc as globs, which
// select .ssh from the home folder: Claude Code's Bash tool (Git Bash) work
// there was a protected target in action mode. Neither PowerShell nor Git
// Bash expands those words. A cmdlet's wildcard path and a redirect still
// count.
func TestActionWindowsQuotedPatternsOfNativeProgramsAreText(t *testing.T) {
	const home = `C:\Users\u`
	for _, tc := range []struct {
		name, command, want string
	}{
		{"echo a quoted star", `echo "*"`, ""},
		{"grep a patch marker", `grep -rn "*** Begin Patch" .`, ""},
		{"rg a quoted glob", `rg -n '*.md' .`, ""},
		{"git pathspec", `git add "*"`, ""},
		{"apply_patch heredoc", "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: notes.txt\n+hi\n*** End Patch\nEOF", ""},
		{"apply_patch heredoc to the key", "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: .ssh/authorized_keys\n+k\n*** End Patch\nEOF", "protected-target"},
		{"cmdlet wildcard path", `Remove-Item "*"`, "protected-target"},
		{"alias wildcard path", `rm "*"`, "protected-target"},
		{"redirect to a quoted pattern", `echo k > "*"`, "protected-target"},
		{"cmdlet key pattern", `Copy-Item payload "*\authorized_keys"`, "protected-target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, home, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}
