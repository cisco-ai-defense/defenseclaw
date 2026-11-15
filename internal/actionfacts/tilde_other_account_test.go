// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestOtherAccountTildeResolvesToItsHome (rel-1-0-10:GAP-0837): ~bob and ~root
// name the home of that account, found by where the home of the active account
// sits, so the path rules read the file the shell opens. A home that sits
// nowhere known leaves the prefix unresolved (no path fact), never a guess.
func TestOtherAccountTildeResolvesToItsHome(t *testing.T) {
	for _, tc := range []struct {
		name, command, home, want string
	}{
		{"user", "cat ~bob/.aws/credentials", "/home/alice", "/home/bob/.aws/credentials"},
		{"root", "cat ~root/.netrc", "/home/alice", "/root/.netrc"},
		{"root agent", "cat ~bob/.netrc", "/root", "/home/bob/.netrc"},
		{"macOS user", "cat ~bob/.netrc", "/Users/alice", "/Users/bob/.netrc"},
		{"active user stays with the twin", "cat ~alice/.netrc", "/home/alice", ""},
		{"home that tells nothing", "cat ~bob/.netrc", "/var/lib/svc", ""},
	} {
		facts := Analyze(Input{Tool: "Bash", Command: tc.command, CWD: "/home/alice/proj", ActiveHome: tc.home, DialectHint: DialectPOSIX})
		got := ""
		for _, p := range facts.Paths {
			if p.Access == PathAccessRead && p.Resolved != "" {
				got = p.Resolved
			}
		}
		if got != tc.want {
			t.Errorf("%s: %q resolves to %q, want %q", tc.name, tc.command, got, tc.want)
		}
	}
}
