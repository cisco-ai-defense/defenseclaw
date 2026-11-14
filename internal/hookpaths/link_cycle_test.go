// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import "testing"

// A link that points at itself or below itself reaches no file, so it is not
// an alias; every other link stays one (rel-1-0-10:GAP-0018).
func TestLinkPointsIntoItselfIsNotAnAlias(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"target below the link name", []string{"-s", "/data/ws/dir1", "/data/ws"}, 0},
		{"sibling target", []string{"-s", "/data/ws/dir1", "/data/other"}, 1},
		{"parent target", []string{"-s", "/data", "/data/ws"}, 1},
		{"link to the keys file", []string{"-s", "/home/alice/.ssh/authorized_keys", "/data/note"}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			links := shellLinks{known: true}
			if !links.add("ln", test.args, "/work") {
				t.Fatal("ln operands were not parsed")
			}
			if len(links.aliases) < test.want {
				t.Fatalf("aliases = %+v, want at least %d", links.aliases, test.want)
			}
			if test.want == 0 && len(links.aliases) != 0 {
				t.Fatalf("aliases = %+v, want none", links.aliases)
			}
		})
	}
}
