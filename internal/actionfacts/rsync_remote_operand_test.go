// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path/filepath"
	"testing"
)

// TestRsyncRemoteOperandKeepsLocalPathsOnTheHost pins that a path of this
// host (a Windows drive path on Windows) is a local rsync operand, while
// host:path, host::module and rsync:// stay remote.
func TestRsyncRemoteOperandKeepsLocalPathsOnTheHost(t *testing.T) {
	t.Parallel()
	local := filepath.Join(t.TempDir(), "settings.json")
	for _, tc := range []struct {
		operand string
		remote  bool
	}{
		{local, false},
		{filepath.ToSlash(local), false},
		{"notes.txt", false},
		{"host:notes.txt", true},
		{"host::module/notes.txt", true},
		{"rsync://host/module", true},
	} {
		if got := rsyncRemoteOperand(tc.operand); got != tc.remote {
			t.Errorf("%q: remote=%t, want %t", tc.operand, got, tc.remote)
		}
	}
}
