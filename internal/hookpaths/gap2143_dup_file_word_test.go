// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

// GAP-2143: bash writes the file of >&word and 1>&word, so the managed hook
// lists it like the &> target; descriptor copies list nothing.
func TestShellWriteOperandsAggregateDuplicateFileWord(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	target := filepath.Join(home, ".defenseclaw", "config.yaml")
	for _, tc := range []struct {
		command string
		want    bool
		dynamic bool
	}{
		{"true >& ~/.defenseclaw/config.yaml", true, false},
		{"true 1>& ~/.defenseclaw/config.yaml", true, false},
		{`true >& "$HOME/.defenseclaw/config.yaml"`, true, false},
		{"echo x 1>&$HOME/.defenseclaw/config.yaml", true, false},
		{"ls 2>&1 >& ~/.defenseclaw/config.yaml", true, false},
		{"ls >& ~/.defenseclaw/config.yaml 2>&1", true, false},
		{"true &> ~/.defenseclaw/config.yaml", true, false},
		{"echo x >&2", false, false},
		{"echo x 1>&2", false, false},
		{"echo x 2>&1", false, false},
		{"exec 3>&-", false, false},
		{`echo x >&"$fd"`, false, false},
		{"echo x >&$fd", false, false},
		{`echo x >& "$dir/f"`, false, true},
	} {
		operands, ok, dynamic := ShellWriteOperands(tc.command, cwd, home)
		if !ok || slices.Contains(operands, target) != tc.want || dynamic != tc.dynamic {
			t.Errorf("ShellWriteOperands(%q) = %v, %t, dynamic %t; want target %t, dynamic %t",
				tc.command, operands, ok, dynamic, tc.want, tc.dynamic)
		}
	}
}
