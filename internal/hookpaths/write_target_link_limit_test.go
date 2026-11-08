// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The walk of a write target follows as many links as the system does:
// a chain the system opens is resolved to its file, and a chain past the
// system limit is unresolvable (rel-1-0-9:GAP-0910).
func TestWriteTargetWalkFollowsAsManyLinksAsTheSystemOpens(t *testing.T) {
	limit := maxWriteTargetLinkDepth()
	dir := t.TempDir()
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

func sameResolvedPath(a, b string) bool {
	left, errLeft := os.Stat(a)
	right, errRight := os.Stat(b)
	return errLeft == nil && errRight == nil && os.SameFile(left, right)
}
