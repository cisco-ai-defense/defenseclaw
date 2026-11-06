// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0518LateCandidateText(t *testing.T) {
	home := t.TempDir()
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
		{"cat project/authorized_keys", false},
	} {
		command := strings.ReplaceAll(row.text, "/home/test", home)
		calls, known := LateKnownCalls(command, home, home)
		got := !known
		memo := NewTargetMemo()
		for _, words := range calls {
			for i, word := range words {
				if i == 0 || word == "" {
					continue
				}
				path := word
				if !filepath.IsAbs(path) {
					path = filepath.Join(home, path)
				}
				got = got || ProtectedReach(path, home, memo) != GradeNone
			}
		}
		if got != row.want {
			t.Errorf("candidate %q = %t, want %t", row.text, got, row.want)
		}
	}
}
