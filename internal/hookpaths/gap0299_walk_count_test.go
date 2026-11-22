// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/workcount"
)

// TestGAP0299MemoWalkBuildsOneKey is the counted-work bound of the memo
// walk (rel-1-0-10:GAP-0299): a walk through the target memo builds the key
// of its whole path once and copies the link stack at most once, whatever
// the depth of the path and however much of it the memo already knows. It
// built a key per component and copied the stack per known prefix before.
func TestGAP0299MemoWalkBuildsOneKey(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c", "d", "e", "f")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	memo := newTargetMemo()
	before := workcount.Take()
	for round := 0; round < 2; round++ {
		for i := 0; i < 200; i++ {
			if _, _, _, ok := walkWritePathMemo("", filepath.Join(deep, "g", fmt.Sprintf("word%d", i)), 0, false, false, memo); !ok {
				t.Fatalf("walk %d failed", i)
			}
		}
	}
	walks, keys := before.Since(workcount.MemoWalk), before.Since(workcount.WalkKey)
	t.Logf("COUNTED walks=%d keys=%d", walks, keys)
	if walks != 400 {
		t.Fatalf("memo walks = %d, want 400", walks)
	}
	if keys > 2*walks {
		t.Fatalf("memo key and stack builds = %d for %d walks, bound 2 per walk", keys, walks)
	}
}
