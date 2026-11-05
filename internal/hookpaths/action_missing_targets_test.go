// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLargeTouchRangeChecksPresentLinksAndProtectedNames(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		{"missing", "touch {1..300}", false},
		{"linked-member", "touch {1..300}", true},
		{"placed-linked-member", "cd nested; touch {1..300}", true},
		{"protected-name", "touch ../.ssh/authorized_key{s,x} {1..300}", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if row.name == "linked-member" {
				if err := os.Symlink(keys, filepath.Join(cwd, "173")); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(filepath.Join(cwd, "173")) })
			}
			if row.name == "placed-linked-member" {
				nested := filepath.Join(cwd, "nested")
				if err := os.Mkdir(nested, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(keys, filepath.Join(nested, "173")); err != nil {
					t.Fatal(err)
				}
			}
			got := ActionCommandDecision(row.command, cwd, home) == "protected-target"
			if got != row.block {
				t.Errorf("%q block=%t, want %t", row.command, got, row.block)
			}
		})
	}
}
