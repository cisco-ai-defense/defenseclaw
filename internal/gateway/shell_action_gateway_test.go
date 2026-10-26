// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestR104ShellClassProtectedWrite covers the consolidated G-hooks-wp class
// rule for nested and scripted shells (GAP-0495 and the shell script/stdin
// finding). In action mode a shell command is ALLOWED only when every write
// target is fully resolved and none is protected: a protected write inside a
// shell -c body, through any recognized shell, option-bearing or wrapped
// invocation, or a local script file, fails closed. Benign bodies and scripts
// with no protected reach stay allowed.
//
// Each blocked row below is a write to cwd/alias, a symlink to the active
// user's authorized_keys; each allowed row writes an ordinary project file.
// Every row is judged on the per-user route and both managed routes.
func TestR104ShellClassProtectedWrite(t *testing.T) {
	skipNativeWindowsHomeGrammar(t)
	home, cwd := r104ReviewHome(t)
	// Local scripts the shell would run: one writes the protected link, one a
	// project file. readIndirectSource reads these as regular files under cwd.
	if err := os.WriteFile(filepath.Join(cwd, "writer.sh"), []byte("echo marker >> alias\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "ordinary.sh"), []byte("echo marker >> report.txt\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		// Other shells: a protected -c body fails closed (zsh is not modeled
		// from argv, so its body write must still block).
		{"zsh -c protected", `zsh -c 'echo marker >> alias'`, true},
		{"ksh -c protected", `ksh -c 'echo marker >> alias'`, true},
		{"dash -c protected", `dash -c 'echo marker >> alias'`, true},
		// Wrappers around a login shell with a protected body.
		{"env bash -lc protected", `env bash -lc 'echo marker >> alias'`, true},
		{"nice bash -lc protected", `nice bash -lc 'echo marker >> alias'`, true},
		{"timeout bash -lc protected", `timeout 5 bash -lc 'echo marker >> alias'`, true},
		// Options the proof does not fully model leave the child unresolved.
		{"bash --rcfile value -c protected", `bash --rcfile /tmp/x -c 'echo marker >> alias'`, true},
		{"bash -o posix -c protected", `bash -o posix -c 'echo marker >> alias'`, true},
		// A local script file is read and inspected like awk -f.
		{"bash script writes protected", `bash writer.sh`, true},
		{"bash ./script writes protected", `bash ./writer.sh`, true},
		{"sh script writes protected", `sh writer.sh`, true},
		// Controls: benign bodies and scripts with no protected reach allow.
		{"zsh -c ordinary", `zsh -c 'echo marker >> report.txt'`, false},
		{"env bash -lc ordinary", `env bash -lc 'echo marker >> report.txt'`, false},
		{"bash ordinary script", `bash ordinary.sh`, false},
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
