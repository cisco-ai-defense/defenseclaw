// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package tactics

import "testing"

// TestRunsProgramLookupRunsNothing is gas-ux-r1 GAP-0055: command -v and
// command -V print how a name resolves and run nothing, so a lookup of a
// program does not count as running it. The program run through command,
// command -p, a wrapper, a list or a shell script still counts, and so does
// a lookup option the reader cannot read (it fails closed).
func TestRunsProgramLookupRunsNothing(t *testing.T) {
	for _, row := range []struct {
		command string
		want    bool
	}{
		{"command -v unzip", false},
		{"command -V unzip", false},
		{"command -pv unzip", false},
		{"command -v -p unzip x.zip", false},
		{"command -v unzip x.zip", false},
		{"command -v unzip && command -v tar", false},
		{"command -v unzip || exit 1", false},
		{"sudo command -v unzip", false},
		{"env command -v unzip", false},
		{"sh -c 'command -v unzip'", false},
		{"x=$(command -v unzip)", false},
		{"command unzip x.zip", true},
		{"command -p unzip x.zip", true},
		{"command -- unzip x.zip", true},
		{"command -v unzip; unzip x.zip", true},
		{"command -v unzip && sudo unzip x.zip", true},
		{"sh -c 'command -v unzip && unzip x.zip'", true},
		{"command -v$X unzip", true},
		{"command $OPT unzip", true},
		{"unzip x.zip", true},
		{"env unzip", true},
	} {
		if got := RunsProgram(row.command, "unzip"); got != row.want {
			t.Errorf("RunsProgram(%q, unzip) = %t, want %t", row.command, got, row.want)
		}
	}
}
