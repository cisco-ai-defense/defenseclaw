// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP0299WalkMemoMatchesFreshWalk is the oracle of the memo walk's
// prefix keys (rel-1-0-10:GAP-0299): its keys are substrings of one key of
// the whole path, so for every path a memo walk, cold or warm, answers what
// a fresh walk of the file system answers, through links to folders, links
// up, absolute and dangling links, a link loop, "..", "." and missing names.
func TestGAP0299WalkMemoMatchesFreshWalk(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"a/b/c", "d"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "a", "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"a/up": "..", "a/tod": "../d", "d/abs": filepath.Join(root, "a", "b"),
		"loop": "loop", "dangle": "nowhere/x", "a/b/self": ".",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, filepath.FromSlash(name))); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	parts := []string{"a", "b", "c", "d", "f", "up", "tod", "abs", "loop", "dangle", "self", "..", ".", "", "missing", "x"}
	rng := rand.New(rand.NewPCG(1, 299))
	memo := newTargetMemo()
	for i := 0; i < 6000; i++ {
		var path strings.Builder
		path.WriteString(root)
		for n := 1 + rng.IntN(7); n > 0; n-- {
			path.WriteString("/")
			path.WriteString(parts[rng.IntN(len(parts))])
		}
		value := filepath.FromSlash(path.String())
		wantPath, _, wantDepth, wantOK := walkWritePath("", value, 0, false, false)
		for round := 0; round < 2; round++ {
			gotPath, _, gotDepth, gotOK := walkWritePathMemo("", value, 0, false, false, memo)
			if gotPath != wantPath || gotDepth != wantDepth || gotOK != wantOK {
				t.Fatalf("%q round %d: memo walk = %q %d %v, fresh walk = %q %d %v",
					value, round, gotPath, gotDepth, gotOK, wantPath, wantDepth, wantOK)
			}
		}
	}
	if len(memo.prefixes) == 0 {
		t.Fatal("the memo kept no prefix: the test walked nothing through it")
	}
}
