// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A link can be retargeted between two scans of one evaluation. Every scan
// drops what the earlier ones answered (the reads of names, the resolved
// operand paths, the key file paths), so the decision judges the link as it
// is when it is made, and answers as without a memo (rel-1-0-9:GAP-0943).
func TestLinkRetargetedBetweenScansIsJudgedAsItIsNow(t *testing.T) {
	type tree struct{ home, project, keys, ordinary, alias string }
	setup := func(t *testing.T) tree {
		t.Helper()
		home, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		tr := tree{home: home, project: filepath.Join(home, "project")}
		tr.keys = filepath.Join(home, ".ssh", "authorized_keys")
		tr.ordinary = filepath.Join(tr.project, "ordinary")
		tr.alias = filepath.Join(tr.project, "alias")
		for _, dir := range []string{tr.project, filepath.Dir(tr.keys)} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, path := range []string{tr.keys, tr.ordinary} {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return tr
	}
	// run scans the state, changes the tree, then decides on the shared memo
	// and on a fresh one.
	run := func(t *testing.T, tr tree, change func()) (shared, fresh string) {
		t.Helper()
		memo := NewTargetMemo()
		end := HookCall()
		defer end()
		if memo.ActionStateTargetMention("touch alias", tr.project, tr.home) {
			t.Fatal("the alias was taken for active state")
		}
		change()
		shared = memo.ActionCommandDecisionInShell("touch alias", tr.project, tr.home, nil, true)
		fresh = NewTargetMemo().ActionCommandDecisionInShell("touch alias", tr.project, tr.home, nil, true)
		return shared, fresh
	}
	relink := func(t *testing.T, target, link string) {
		t.Helper()
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("a name that became a link to the keys file is blocked", func(t *testing.T) {
		tr := setup(t)
		if err := os.Symlink(tr.ordinary, tr.alias); err != nil {
			t.Skipf("symlink: %v", err)
		}
		shared, fresh := run(t, tr, func() { relink(t, tr.keys, tr.alias) })
		if shared == "" || fresh == "" {
			t.Fatalf("a link to the keys file: shared memo %q, fresh memo %q, want both blocked", shared, fresh)
		}
	})
	t.Run("a name that became a link to an ordinary file is allowed", func(t *testing.T) {
		tr := setup(t)
		if err := os.Symlink(tr.keys, tr.alias); err != nil {
			t.Skipf("symlink: %v", err)
		}
		shared, fresh := run(t, tr, func() { relink(t, tr.ordinary, tr.alias) })
		if shared != "" || fresh != "" {
			t.Fatalf("a link to an ordinary file: shared memo %q, fresh memo %q, want both allowed", shared, fresh)
		}
	})
	t.Run("a hard link to the file the keys file no longer is stays allowed", func(t *testing.T) {
		tr := setup(t)
		oldTarget := filepath.Join(tr.home, "old-key-target")
		newTarget := filepath.Join(tr.home, "new-key-target")
		for _, path := range []string{oldTarget, newTarget} {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Remove(tr.keys); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(oldTarget, tr.keys); err != nil {
			t.Skipf("symlink: %v", err)
		}
		if err := os.Link(oldTarget, tr.alias); err != nil {
			t.Skipf("hard link: %v", err)
		}
		shared, fresh := run(t, tr, func() { relink(t, newTarget, tr.keys) })
		if shared != "" || fresh != "" {
			t.Fatalf("a hard link to the old key target: shared memo %q, fresh memo %q, want both allowed", shared, fresh)
		}
	})
}

// The folder proof is per scan: a folder found plain by one scan that becomes
// a link to a share before the next scan is asked by that scan.
func TestShareFolderProvenByOneScanIsAskedAgainByTheNext(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	defer end()
	memo := NewTargetMemo()
	memo.beginScan()
	for i := range 50 {
		if _, err := memo.lstat(filepath.Join(fx.slot, fmt.Sprintf("f%d", i))); errors.Is(err, errNetworkShareUnanswered) {
			t.Fatalf("an ordinary operand is read as a share: %v", err)
		}
	}
	if err := os.Rename(fx.slot, fx.slot+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fx.share, fx.slot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	memo.beginScan()
	if _, err := memo.lstat(filepath.Join(fx.slot, "skills")); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("read below the swapped folder in the next scan = %v, want the share error", err)
	}
	if got := fx.probes(); got != 1 {
		t.Fatalf("%d probes, want one", got)
	}
}
