// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1742: after a top-level cd, a link of plain files made every name
// opaque, so `cd D && ln a b` was an SSH authorized keys mutation in action
// mode. The link is now placed in the directory the cd names and judged by
// its own source and destination: a link creation is a protected write only
// when one of them resolves to a protected target.
func TestR105LinkAfterCDIsJudgedByItsOperands(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.Mkdir(filepath.Join(cwd, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"hard link", "cd build && ln ../a.txt b1", false},
		{"symbolic link", "cd build && ln -s ../a.txt b4", false},
		{"hard link then append", "cd build && ln ../a.txt b5 && echo hi >> b5", false},
		{"absolute cd", "cd " + filepath.Join(cwd, "build") + " && ln ../a.txt b9", false},
		{"link to the key alias then append", "cd build && ln -s ../alias b6 && echo x >> b6", true},
		{"link to authorized_keys then append", "cd build && ln -s ../../.ssh/authorized_keys b7 && echo x >> b7", true},
		{"dynamic cd keeps the opaque scope", `cd "$D" && ln -s ../alias b8 && echo x >> b8`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.blocked {
					t.Fatalf("decision %d (per-user, managed claudecode, managed codex) = %v, want %v", i, got, tc.blocked)
				}
			}
		})
	}
}
