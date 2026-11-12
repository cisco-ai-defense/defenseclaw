// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRegistrationFindReachWalkAndChild pins that a find walk reaches a
// registered file only as deep as its -maxdepth lets it, and that an -exec
// removal reaches what the walk found only when the child is handed the found
// name ({}): a child that names its own operands is judged on those.
func TestRegistrationFindReachWalkAndChild(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	hook := filepath.Join(home, "agent", "conf", "hook.json")
	other := filepath.Join(root, "scratch", "a.tmp")
	for _, path := range []string{hook, other} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{hook}
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"walk with a removal of the found name", "find " + root + " -name hook.json -exec rm -f {} +", true},
		{"delete walk", "find " + root + " -name hook.json -delete", true},
		{"walk cut before the hook", "find " + root + " -maxdepth 2 -delete", false},
		{"walk cut at the hook depth", "find " + home + " -maxdepth 3 -delete", true},
		{"walk that stops at its roots", "find " + root + " -maxdepth 0 -delete", false},
		{"walk that stops at its roots with a removal of the found name", "find " + root + " -maxdepth 0 -exec rm {} \\;", false},
		{"walk that stops at its roots with a recursive removal of the found name", "find " + root + " -maxdepth 0 -exec rm -rf {} \\;", true},
		{"walk that stops at its roots with a long recursive removal of the found name", "find " + root + " -maxdepth 0 -exec rm --recursive {} \\;", true},
		{"walk that stops at its roots with a move of the found name", "find " + root + " -maxdepth 0 -exec mv {} /var/aside \\;", true},
		{"child removing its own operand under a walked folder", "find " + root + " -maxdepth 0 -exec rm -rf " + other + " \\;", false},
		{"child removing its own operand under an unbounded walk", "find " + root + " -exec rm -f " + other + " \\;", false},
		{"child removing the hook by name", "find " + root + " -maxdepth 0 -exec rm -f " + hook + " \\;", true},
		{"unbounded delete walk", "find " + root + " -delete", true},
		{"depth that is not a number", "find " + root + " -maxdepth $N -delete", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := len(RegistrationWriteReached(tc.command, root, home, names)) > 0
			if got != tc.want {
				t.Fatalf("%s: reached=%t, want %t", tc.command, got, tc.want)
			}
		})
	}
}
