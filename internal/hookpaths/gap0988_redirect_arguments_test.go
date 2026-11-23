// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestGAP0988RedirectOwnStatementHasNoInnerCommand(t *testing.T) {
	root := t.TempDir()
	for _, row := range []struct {
		name, command string
		noInner       bool
	}{
		{"plain", "echo hi > out.txt", true},
		{"subexpression", "echo $(pwd) > out.txt", false},
		{"backtick", "echo `pwd` > out.txt", false},
		{"process-substitution", "cat <(pwd) > out.txt", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := SafeShellRedirectOccurrences(row.command, root, root)
			if len(got) != 1 {
				t.Fatalf("redirects=%d, want 1", len(got))
			}
			if got[0].NoInnerCommand != row.noInner {
				t.Errorf("no inner command=%v, want %v", got[0].NoInnerCommand, row.noInner)
			}
			if !row.noInner && got[0].Safe {
				t.Error("inner command granted opens-before proof")
			}
		})
	}
}
