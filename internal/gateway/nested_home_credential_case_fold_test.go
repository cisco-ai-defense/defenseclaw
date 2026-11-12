// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// On a case-folding host the folders and names are read in any letter case; on
// a case-sensitive one a different case names another file.
func TestNestedHomeCredentialBelowTheWorkingDirectoryFollowsTheHostLetterCase(t *testing.T) {
	const home, cwd = "/Users/alice", "/Users/alice/project"
	installToolCallCorpusProfileConnector(t, "nested-home-case", "default")
	for _, fold := range []bool{true, false} {
		withPathCaseFoldHost(t, fold)
		for _, relative := range []string{"USERS/ALICE/.NETRC", "users/Alice/.Git-Credentials", "a/uSeRs/alice/.AWS/CREDENTIALS"} {
			for _, directive := range []string{"", "Add File"} {
				action, rules := nestedHomeVerdict(t, "nested-home-case", directive, home, cwd, cwd+"/"+relative)
				if fold && (action != "block" || len(rules) == 0) {
					t.Errorf("case-folding host %q %q: %s %v, want a block", directive, relative, action, rules)
				}
				if !fold && action != "allow" {
					t.Errorf("case-sensitive host %q %q: %s %v, want allow (another file)", directive, relative, action, rules)
				}
			}
		}
	}
}
