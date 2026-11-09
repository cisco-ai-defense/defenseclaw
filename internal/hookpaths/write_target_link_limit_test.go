// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The walk of a write target follows as many links as the system does:
// a chain the system opens is resolved to its file, and a chain past the
// system limit is unresolvable (rel-1-0-9:GAP-0910).
func TestWriteTargetWalkFollowsAsManyLinksAsTheSystemOpens(t *testing.T) {
	limit := SystemLinkLimit()
	dir := linkFreeTempDir(t)
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The links are made from the last to the first so each target exists
	// when its link is made (Windows makes a link to a missing file a file
	// link, and a file link to another link cannot be opened).
	chain := func(n int) string {
		base := filepath.Join(dir, fmt.Sprint("chain", n))
		if err := os.Mkdir(base, 0o700); err != nil {
			t.Fatal(err)
		}
		name := func(i int) string { return filepath.Join(base, fmt.Sprintf("hop%03d", i)) }
		for i := n; i >= 1; i-- {
			to := file
			if i < n {
				to = name(i + 1)
			}
			if err := os.Symlink(to, name(i)); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
		}
		return name(1)
	}
	for _, tc := range []struct {
		links   int
		resolve bool
	}{
		{1, true},
		{limit - 1, true},
		{limit, true},
		{limit + 1, false},
	} {
		first := chain(tc.links)
		if tc.resolve {
			if _, err := os.Stat(first); err != nil {
				t.Fatalf("the system does not open a chain of %d links: %v", tc.links, err)
			}
		}
		resolved, ok := resolveWritePath(first, 0)
		if ok != tc.resolve {
			t.Errorf("a chain of %d links (system limit %d): resolved=%v, want %v", tc.links, limit, ok, tc.resolve)
		}
		if ok {
			if want, _ := filepath.EvalSymlinks(file); !sameResolvedPath(resolved, want) {
				t.Errorf("a chain of %d links resolves to %q, want %q", tc.links, resolved, want)
			}
		}
	}
}

// A path spelled through a folder behind links and then a name of links of
// its own is a write the system makes from a process that stands in the
// folder: the name opens relative to it, with a limit of its own. The walk
// counts the links of the name from the folder, at every split of the limit,
// so the name is resolved, not called unresolvable (rel-1-0-9:GAP-0935). A
// single chain past the limit, and a loop, stay unresolvable.
func TestWriteTargetWalkCountsALinkFromTheFolderTheProcessStandsIn(t *testing.T) {
	limit := SystemLinkLimit()
	dir := linkFreeTempDir(t)
	folder := filepath.Join(dir, "folder")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(folder, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(folder, "alias")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, links := range []int{1, limit - 1, limit} {
		through := localLinkChain(t, linkFreeTempDir(t), links, folder)
		resolved, ok := resolveWritePath(filepath.Join(through, "alias"), 0)
		if !ok || !sameResolvedPath(resolved, file) {
			t.Errorf("alias behind %d links: resolved %q ok=%v, want the file it links to", links, resolved, ok)
		}
	}
	// The same at every split of the limit between the folder and a name of
	// two links: the process opens the name from the folder, so the folder
	// may cost any number of links up to the limit.
	if err := os.Symlink(file, filepath.Join(folder, "second")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(folder, "second"), filepath.Join(folder, "first")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for links := 1; links <= limit; links++ {
		through := localLinkChain(t, linkFreeTempDir(t), links, folder)
		resolved, ok := resolveWritePath(filepath.Join(through, "first"), 0)
		if !ok || !sameResolvedPath(resolved, file) {
			t.Errorf("two-link name behind %d folder links: resolved %q ok=%v, want the file it links to", links, resolved, ok)
		}
	}
	beyond := localLinkChain(t, linkFreeTempDir(t), limit+1, folder)
	if resolved, ok := resolveWritePath(filepath.Join(beyond, "alias"), 0); ok {
		t.Errorf("alias behind a chain of %d links resolved to %q, want unresolvable", limit+1, resolved)
	}
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if resolved, ok := resolveWritePath(filepath.Join(loop, "x"), 0); ok {
		t.Errorf("a link loop resolved to %q, want unresolvable", resolved)
	}
}

// linkFreeTempDir is a temp folder whose own path crosses no link (macOS
// keeps /var, and so every temp folder, behind one), so the links a test
// counts are the ones it makes.
func linkFreeTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		return dir
	}
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// SystemLinkLimit is the limit of the system the test runs on, not a number
// the code and the test agree on: one chain longer than any system opens is
// made, and the most links that open from it are counted. A disagreement
// fails here, on the runner of the system it is wrong for.
func TestSystemLinkLimitIsTheLimitTheRunnerOpens(t *testing.T) {
	const longest = 80
	dir := linkFreeTempDir(t)
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := func(i int) string { return filepath.Join(dir, fmt.Sprintf("hop%03d", i)) }
	for i := longest; i >= 1; i-- {
		to := file
		if i < longest {
			to = name(i + 1)
		}
		if err := os.Symlink(to, name(i)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	// name(i) crosses longest-i+1 links.
	opens := 0
	for i := longest; i >= 1; i-- {
		if _, err := os.Stat(name(i)); err != nil {
			break
		}
		opens = longest - i + 1
	}
	if opens != SystemLinkLimit() {
		t.Fatalf("%s opens a path of at most %d links, SystemLinkLimit is %d", runtime.GOOS, opens, SystemLinkLimit())
	}
}

func sameResolvedPath(a, b string) bool {
	left, errLeft := os.Stat(a)
	right, errRight := os.Stat(b)
	return errLeft == nil && errRight == nil && os.SameFile(left, right)
}
