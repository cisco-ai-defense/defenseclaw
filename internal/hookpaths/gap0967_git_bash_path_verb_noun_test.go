// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A Verb-Noun word after a slash is a path component of a program both
// shells run, not a PowerShell cmdlet, so it does not take a Git Bash call
// out of its POSIX reading; a cmdlet word still does (rel-1-0-10:GAP-0967,
// probe row U22 of the gateway's
// TestUnmodelledProgramWithAKeysOperandIsUnknownRole).
func TestGAP0967GitBashPathVerbNounIsNoCmdlet(t *testing.T) {
	for _, tc := range []struct {
		text       string
		powerShell bool
	}{
		{"/opt/tools/add-key notes.txt", false},
		{"./bin/set-up --dry-run", false},
		{"~/scripts/get-deps.sh", false},
		{"Add-Content notes.txt x", true},
		{"git status; Set-Content notes.txt x", true},
		{"echo x | add-content notes.txt", true},
		{"(Get-Item notes.txt).Length", true},
		{"$x = 1", true},
	} {
		if got := actionGitBashPowerShellSyntax.MatchString(tc.text); got != tc.powerShell {
			t.Errorf("%q: PowerShell syntax = %v, want %v", tc.text, got, tc.powerShell)
		}
	}
}
