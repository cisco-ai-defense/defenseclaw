// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// The scans of one evaluation share a TargetMemo, and a second process can
// change the keys file or a name between two of them. The identity of the
// protected keys file is read again by each scan like the identity of the
// operand, so a name is judged against the keys file as it is when the
// decision is made and the shared memo answers as a fresh one
// (rel-1-0-9:GAP-0943).
func TestProtectedFileIdentityChangedBetweenScansIsJudgedAsItIsNow(t *testing.T) {
	for _, tc := range []struct {
		name               string
		keysAtStart        bool
		aliasToKeysAtStart bool
		change             func(t *testing.T, keys, alias string)
		wantBlock          bool
	}{
		{
			name: "a keys file created after the first scan protects the name linked to it",
			change: func(t *testing.T, keys, alias string) {
				t.Helper()
				writeScanFile(t, keys, "new key")
				removeScanFile(t, alias)
				linkScanFile(t, keys, alias)
			},
			wantBlock: true,
		},
		{
			name:        "a keys file replaced after the first scan protects the name linked to the new one",
			keysAtStart: true,
			change: func(t *testing.T, keys, alias string) {
				t.Helper()
				removeScanFile(t, keys)
				writeScanFile(t, keys, "new key")
				removeScanFile(t, alias)
				linkScanFile(t, keys, alias)
			},
			wantBlock: true,
		},
		{
			name:        "a name linked to the old keys file is ordinary once the keys file is replaced",
			keysAtStart: true, aliasToKeysAtStart: true,
			change: func(t *testing.T, keys, _ string) {
				t.Helper()
				removeScanFile(t, keys)
				writeScanFile(t, keys, "new key")
			},
			wantBlock: false,
		},
		{
			name:        "a name that became a symbolic link to the keys file is blocked",
			keysAtStart: true,
			change: func(t *testing.T, keys, alias string) {
				t.Helper()
				removeScanFile(t, alias)
				if err := os.Symlink(keys, alias); err != nil {
					t.Skipf("symlink: %v", err)
				}
			},
			wantBlock: true,
		},
		{
			name:        "a name that stays ordinary while the keys file is replaced is allowed",
			keysAtStart: true,
			change: func(t *testing.T, keys, _ string) {
				t.Helper()
				removeScanFile(t, keys)
				writeScanFile(t, keys, "new key")
			},
			wantBlock: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			project := filepath.Join(home, "project")
			keys := filepath.Join(home, ".ssh", "authorized_keys")
			alias := filepath.Join(project, "alias")
			for _, dir := range []string{project, filepath.Dir(keys)} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.keysAtStart {
				writeScanFile(t, keys, "old key")
			}
			if tc.aliasToKeysAtStart {
				linkScanFile(t, keys, alias)
			} else {
				writeScanFile(t, alias, "ordinary")
			}
			memo := NewTargetMemo()
			if memo.ActionStateTargetMention("touch alias", project, home) {
				t.Fatal("the alias was taken for active state")
			}
			tc.change(t, keys, alias)
			shared := memo.ActionCommandDecisionInShell("touch alias", project, home, nil, true)
			fresh := NewTargetMemo().ActionCommandDecisionInShell("touch alias", project, home, nil, true)
			if (fresh != "") != tc.wantBlock {
				t.Fatalf("fresh memo decision %q, want block=%v", fresh, tc.wantBlock)
			}
			if (shared != "") != (fresh != "") {
				t.Fatalf("shared memo decision %q, fresh memo %q", shared, fresh)
			}
		})
	}
}

func writeScanFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func removeScanFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func linkScanFile(t *testing.T, old, link string) {
	t.Helper()
	if err := os.Link(old, link); err != nil {
		t.Skipf("hard link: %v", err)
	}
}
