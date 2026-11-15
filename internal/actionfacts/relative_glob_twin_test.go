// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// TestRelativeGlobTwinsNamed is the reading of a pathname pattern in a folder
// the call does not give (rel-1-0-10:GAP-0960): each name it may match, as
// the shell matches a component, a pattern of more components keeping its
// leading ones, one reading per match; a pattern with no literal name, a quoted pattern, a home or
// absolute pattern and a leading wildcard before a dot name are no twin.
func TestRelativeGlobTwinsNamed(t *testing.T) {
	names := []string{"credentials", ".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials"}
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{"cp .ssh/id_* /tmp/s", []string{"cp '.ssh/id_ed25519' /tmp/s", "cp '.ssh/id_rsa' /tmp/s"}},
		{"cat .ssh/id_r*a", []string{"cat '.ssh/id_rsa'"}},
		{"cat .ss?/id_rsa", []string{"cat '.ssh/id_rsa'"}},
		{"cat alice/.ssh/id_r*", []string{"cat 'alice/.ssh/id_rsa'"}},
		{"cat .aws/*", []string{"cat '.aws/credentials'"}},
		{"cat cred* .ssh/id_*", []string{"cat 'credentials' '.ssh/id_ed25519'", "cat 'credentials' '.ssh/id_rsa'"}},
		{"cat *", nil},
		{"cat ./*", nil},
		{"cat */*", nil},
		{"cat '.ssh/id_*'", nil},
		{"cat *ssh/id_rsa", nil},
		{"cat ~/.ssh/id_*", nil},
		{"cat /root/.ssh/id_*", nil},
		{"cat *.go", nil},
	} {
		if got := RelativeGlobTwinsNamed(tc.command, "/home/alice", names); !slices.Equal(got, tc.want) {
			t.Errorf("RelativeGlobTwinsNamed(%q) = %q; want %q", tc.command, got, tc.want)
		}
	}
}
