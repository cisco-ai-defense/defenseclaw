// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestDeveloperTokenFileOfAccountHome (rel-1-0-10:GAP-0816, GAP-0836): the
// native file tools take the developer-token files of an account home, found by
// position; a project folder called home, homes or users, a fixture tree, a
// name below the home and a name projects ship are none.
func TestDeveloperTokenFileOfAccountHome(t *testing.T) {
	for value, want := range map[string]bool{
		"/home/u/.git-credentials": true, "/home/u/.netrc": true, "/home/u/.pgpass": true, "/Users/u/_netrc": true,
		"/root/.netrc": true, "C:/Users/u/.git-credentials": true, `C:\Users\u\.netrc`: true,
		"/work/repo/users/bob/.netrc": false, "/work/repo/Users/bob/.git-credentials": false, "/srv/homes/x/.netrc": false,
		"/mnt/home/x/.pgpass": false, "/home/u/proj/.netrc": false, "/home/u/.npmrc": false, "/home/u/.netrc.example": false,
		"/home/u/fixtures/home/bob/.netrc": false, ".netrc": false, "/home": false, "/": false,
	} {
		if got := developerTokenFileOfAccountHome(value); got != want {
			t.Errorf("developerTokenFileOfAccountHome(%q) = %t, want %t", value, got, want)
		}
	}
}
