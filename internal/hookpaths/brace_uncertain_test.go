// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A brace list of plain names is read as the words bash passes: nothing
// uncertain; a list whose alternatives hold a glob form the resolver does not
// model still is (rel-1-0-10:GAP-0350).
func TestBraceListOfPlainNamesIsNotUncertain(t *testing.T) {
	f := newShellWordFixture(t)
	for _, test := range []struct {
		command   string
		uncertain bool
	}{
		{"cp ~/dc-eh/jobs/x/{a.txt,b.txt,c.txt} /tmp/dest/", false},
		{"cp {mutants.sh,gates.sh} .v/", false},
		{"cp a{1,2}.txt b/", false},
		{"cp {a,b[!z]}.txt b/", true},
		{"cp a b/{x,y}[!z]", true},
	} {
		got := UncertainGlobWriteReason(test.command, f.project, f.home, nil) != ""
		if got != test.uncertain {
			t.Errorf("%q: uncertain = %t, want %t", test.command, got, test.uncertain)
		}
	}
}
