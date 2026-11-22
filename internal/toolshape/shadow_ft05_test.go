// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import "testing"

// rel-1-0-10:GAP-1070. A trigger word split by quotes or a backslash is
// still a trigger word: the shell reads sh'ad'ow as shadow.
func TestGAP1070ShellCandidateReadsQuoteSplitWords(t *testing.T) {
	for text, want := range map[string]bool{
		"cat shadow":              true,
		"cd /etc && cat sh'ad'ow": true,
		`cat sh"ad"ow`:            true,
		`cat sha\dow`:             true,
		"cat s''hadow":            true,
		"echo hello 'world'":      false,
		`echo "a b" c\d`:          false,
	} {
		if got := ShellCandidate(text); got != want {
			t.Errorf("ShellCandidate(%q) = %v, want %v", text, got, want)
		}
	}
}
