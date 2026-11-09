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

// Many names below one folder are read with the folder proved once, whichever
// way they are read (rel-1-0-9:GAP-0943, GAP-0963).
func TestFolderProofsReadTheFolderOfManyNamesOnce(t *testing.T) {
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "a", "b", "c", "d")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	reads := countWalkReads(t)
	var proofs folderProofs
	for i := range 1000 {
		name := filepath.Join(folder, fmt.Sprintf("f%d", i))
		if _, err := proofs.lstat(name); !os.IsNotExist(err) {
			t.Fatalf("lstat of a missing name = %v", err)
		}
		if _, err := proofs.stat(name); !os.IsNotExist(err) {
			t.Fatalf("stat of a missing name = %v", err)
		}
	}
	if *reads > 20 {
		t.Fatalf("2000 reads below one folder made %d walk reads, want at most 20", *reads)
	}
}

// A proof answers as the file system does, for a file, a directory, a link
// and a missing name below a plain folder, and below a missing folder.
func TestFolderProofsAnswerAsTheFileSystemDoes(t *testing.T) {
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(folder, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(folder, "file"), filepath.Join(folder, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	names := []string{"file", "dir", "link", "missing"}
	var proofs folderProofs
	for _, name := range names {
		for _, path := range []string{filepath.Join(folder, name), filepath.Join(root, "nofolder", "deeper", name)} {
			for round := range 2 {
				gotL, errL := proofs.lstat(path)
				wantL, werrL := os.Lstat(path)
				if (errL == nil) != (werrL == nil) || os.IsNotExist(errL) != os.IsNotExist(werrL) || errL == nil && gotL.Mode() != wantL.Mode() {
					t.Errorf("round %d lstat %s = %v %v, file system %v %v", round, path, gotL, errL, wantL, werrL)
				}
				gotS, errS := proofs.stat(path)
				wantS, werrS := os.Stat(path)
				if (errS == nil) != (werrS == nil) || os.IsNotExist(errS) != os.IsNotExist(werrS) || errS == nil && gotS.Mode() != wantS.Mode() {
					t.Errorf("round %d stat %s = %v %v, file system %v %v", round, path, gotS, errS, wantS, werrS)
				}
			}
		}
	}
}

// A proof ends with its scope: a folder found missing, and a name found
// missing, are read again by the next scope.
func TestFolderProofsEndWithTheirScope(t *testing.T) {
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "later")
	name := filepath.Join(folder, "file")
	var proofs folderProofs
	if _, err := proofs.stat(name); !os.IsNotExist(err) {
		t.Fatalf("stat below a missing folder = %v", err)
	}
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := proofs.stat(name); !os.IsNotExist(err) {
		t.Fatalf("the scope that found the folder missing answered %v", err)
	}
	proofs.clear()
	if _, err := proofs.stat(name); err != nil {
		t.Fatalf("stat in the next scope = %v, want the file", err)
	}
}

// A folder that is a link to a share is not a proof: a name below it is read
// with the walk and asked, whether or not other folders have been proved.
func TestFolderProofsDoNotCoverALinkToAShare(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	defer end()
	var proofs folderProofs
	for i := range 50 {
		if _, err := proofs.lstat(filepath.Join(fx.project, fmt.Sprintf("f%d", i))); err != nil && !os.IsNotExist(err) {
			t.Fatalf("an ordinary operand: %v", err)
		}
	}
	if err := os.Rename(fx.slot, fx.slot+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fx.share, fx.slot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := proofs.lstat(filepath.Join(fx.slot, "skills")); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("read below a link to a share = %v, want the share error", err)
	}
}
