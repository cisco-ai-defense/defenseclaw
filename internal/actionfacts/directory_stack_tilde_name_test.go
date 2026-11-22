// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestDirectoryStackTildeNameIsNoAccount pins the forms bash takes from the
// dirs list, PWD and OLDPWD before the password database: they never name an
// account's home (rel-1-0-10:GAP-0887).
func TestDirectoryStackTildeNameIsNoAccount(t *testing.T) {
	for _, name := range []string{"", "+", "-", "0", "1", "01", "999", "+0", "+1", "-1", "+12"} {
		if !directoryStackTildeName(name) {
			t.Errorf("~%s: not a directory-stack form", name)
		}
		for _, home := range []string{"/home/alice", "/Users/alice", "/root", "C:/Users/alice"} {
			if other, ok := simpleOtherAccountHome(name, home); ok {
				t.Errorf("~%s with home %s names the account home %s", name, home, other)
			}
		}
	}
	for _, name := range []string{"bob", "1bob", "b1", "_svc", "root", "+x", "1+"} {
		if directoryStackTildeName(name) {
			t.Errorf("~%s: read as a directory-stack form", name)
		}
	}
}
