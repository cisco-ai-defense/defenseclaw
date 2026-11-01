// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// An unexported CDPATH may select a directory elsewhere whose sub/out.txt
// links to authorized_keys. A link of plain files after a top-level cd is not
// a protected write (GAP-1742: the link is judged by its own source and
// destination), so a cd/ln/write chain with no protected-named word is
// allowed on every route; an unexported CDPATH the hook cannot see is a
// documented limit of the pre-tool check. A pushd keeps the conservative
// block.
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
		{"search-path cd", `cd sub && ln -s ../a b && echo marker > out.txt`, false},
		{"search-path cd append", `cd sub && ln -s ../a b && echo marker >> out.txt`, false},
		{"search-path cd other name", `cd sub && ln -s ../a b && echo marker > notes.md`, false},
		{"quoted search-path cd", `cd "sub" && ln -s ../a b && echo marker > out.txt`, false},
		{"trailing slash cd", `cd sub/ && ln -s ../a b && echo marker > out.txt`, false},
		{"nested search-path cd", `cd sub/deeper && ln -s ../../a b && echo marker > out.txt`, false},
		{"dot-dot cd", `cd ../project/sub && ln -s ../a b && echo marker > out.txt`, false},
		{"pushd", `pushd sub && ln -s ../a b && echo marker > out.txt`, true},
		{"explicit cd", `cd ./sub && ln -s ../a b && echo marker > out.txt`, false},
		{"explicit nested cd", `cd ./sub/deeper && ln -s ../../a b && echo marker > out.txt`, false},
		// Forward slashes: backslashes of a native Windows path are shell escapes.
		{"absolute cd", `cd ` + filepath.ToSlash(filepath.Join(cwd, "sub")) + ` && ln -s ../a b && echo marker > out.txt`, false},
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
