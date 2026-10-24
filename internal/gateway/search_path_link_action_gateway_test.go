// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// An unexported CDPATH may select a directory elsewhere whose sub/out.txt
// links to authorized_keys. A cd/ln/write chain through a cd operand that Bash
// may resolve through CDPATH is blocked on every route. An absolute or ./ cd
// names a proven directory, and an ordinary write there stays allowed.
func TestR104Loop3SearchPathCDLinkDecisions(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, dir := range []string{filepath.Join(cwd, "sub", "deeper"), filepath.Join(home, "elsewhere", "sub", "deeper")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cwd, "a"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		filepath.Join(home, "elsewhere", "sub", "out.txt"):           "../../.ssh/authorized_keys",
		filepath.Join(home, "elsewhere", "sub", "deeper", "out.txt"): "../../../.ssh/authorized_keys",
	} {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"search-path cd", `cd sub && ln -s ../a b && echo marker > out.txt`, true},
		{"search-path cd append", `cd sub && ln -s ../a b && echo marker >> out.txt`, true},
		{"search-path cd other name", `cd sub && ln -s ../a b && echo marker > notes.md`, true},
		{"quoted search-path cd", `cd "sub" && ln -s ../a b && echo marker > out.txt`, true},
		{"trailing slash cd", `cd sub/ && ln -s ../a b && echo marker > out.txt`, true},
		{"nested search-path cd", `cd sub/deeper && ln -s ../../a b && echo marker > out.txt`, true},
		{"dot-dot cd", `cd ../project/sub && ln -s ../a b && echo marker > out.txt`, true},
		{"pushd", `pushd sub && ln -s ../a b && echo marker > out.txt`, true},
		{"explicit cd", `cd ./sub && ln -s ../a b && echo marker > out.txt`, false},
		{"explicit nested cd", `cd ./sub/deeper && ln -s ../../a b && echo marker > out.txt`, false},
		{"absolute cd", `cd ` + filepath.Join(cwd, "sub") + ` && ln -s ../a b && echo marker > out.txt`, false},
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
