// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestGAP0518LateCandidateText(t *testing.T) {
	for _, row := range []struct {
		text string
		want bool
	}{
		{"echo hello", false},
		{"cat README.md", false},
		{"cat ~/.ssh/authorized_keys", true},
		{"cat ~/.ss*/auth*", true},
		{"p=$HOME/.ssh/authorized_keys; cat $p", true},
		{"cat /home/test/.defenseclaw/config.yaml", true},
		{"cat project/authorized_keys_notes.txt", false},
		{"cat project/notes.ssh.txt", false},
		{"echo $PWD", false},
		{"printf '%s' \"$USER\"", false},
		{"cat $unknown", true},
		{"cat $PWD/.ssh/config", true},
		{"cat project/authorized_keys", true},
	} {
		if got := CallMayReachProtected(row.text, "/home/test"); got != row.want {
			t.Errorf("candidate %q = %t, want %t", row.text, got, row.want)
		}
	}
}
