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
	} {
		if got := CallMayReachProtected(row.text, "/home/test"); got != row.want {
			t.Errorf("candidate %q = %t, want %t", row.text, got, row.want)
		}
	}
}
