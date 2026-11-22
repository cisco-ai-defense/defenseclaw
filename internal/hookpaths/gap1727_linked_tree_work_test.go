// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// gap1727Tree makes dir with folders empty folders d0000...
func gap1727Tree(t *testing.T, dir string, folders int) {
	t.Helper()
	for index := 0; index < folders; index++ {
		if err := os.MkdirAll(filepath.Join(dir, fmt.Sprintf("d%04d", index)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// gap1727Home is a home with ~/.ssh and a project folder.
func gap1727Home(t *testing.T) (home, project string) {
	t.Helper()
	home = t.TempDir()
	project = filepath.Join(home, "proj")
	for _, dir := range []string{project, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return home, project
}

// GAP-1727: the linked tree walk of a command that makes a link and enters
// it in a nested shell (linkedTreesClear) stopped only at 20,000 entries,
// whatever they cost: a cold walk of a tree of many folders (each one a
// directory read, about 1 ms cold) read past the 3.5 s hook answer deadline.
// The walk now counts the read of each folder as work (linkedTreeDirWork),
// so a tree of 1,300 empty folders (1,301 entries, under the old entry
// bound) is past the bound: its links are not stable. A small tree is still
// read to its end, and a disk link to ~/.ssh in it is still found.
func TestGAP1727LinkedTreeWalkCountsFolderReads(t *testing.T) {
	home, project := gap1727Home(t)
	gap1727Tree(t, filepath.Join(project, "small"), 50)
	gap1727Tree(t, filepath.Join(project, "big"), 1300)
	gap1727Tree(t, filepath.Join(project, "bad"), 50)
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(project, "bad", "d0049", "keys")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		tree   string
		stable bool
	}{
		{"small", true},
		{"bad", false},
		{"big", false},
	} {
		command := "ln -s " + filepath.Join(project, row.tree) + " l && bash -c 'cd l && touch x'"
		links, _ := commandLinksRead(command, project, home, nil, false, false, true)
		if links.movesStable != row.stable {
			t.Errorf("%s: links stable %v, want %v", row.tree, links.movesStable, row.stable)
		}
	}
}

// The linked tree walks of one command reading share one work budget.
func TestGAP1727LinkedTreeWorkIsShared(t *testing.T) {
	home, project := gap1727Home(t)
	// 700 folders: 700*17+1 work, under the bound alone; twice is past it.
	tree := filepath.Join(project, "half")
	gap1727Tree(t, tree, 700)
	state := newStateReach(home)
	if !treesAwayFromState([]string{tree}, state, &linkedTreeWork{}) {
		t.Fatalf("one walk of %s with its own budget is not clear", tree)
	}
	work := &linkedTreeWork{}
	first := treesAwayFromState([]string{tree}, state, work)
	second := movedEntriesAwayFromState(nil, []findMove{{starts: []string{tree}, pattern: "nomatch"}}, home, work)
	if !first || second {
		t.Errorf("shared budget: first walk clear=%v, second clear=%v, want true, false", first, second)
	}
}
