// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/workcount"
)

// TestGAP0299WordReadOnceForWalkAndStateEntry is the counted-work bound of
// a word's file lookups (rel-1-0-10:GAP-0299): the state scan reads the
// entry of each word the write-target walk of the same call has just read,
// and the two share one Lstat. Its answers stay those of a fresh read for
// files, links (to a file, a folder, nowhere) and missing names, and two
// evaluations of one call (NewTargetMemoIn) walk each word once.
func TestGAP0299WordReadOnceForWalkAndStateEntry(t *testing.T) {
	dir := t.TempDir()
	var words []string
	for i := 0; i < 100; i++ {
		name := filepath.Join(dir, fmt.Sprintf("word%d", i))
		var err error
		switch i % 5 {
		case 0:
			err = os.WriteFile(name, nil, 0o600)
		case 1:
			err = os.Symlink(filepath.Join(dir, "word0"), name)
		case 2:
			err = os.Symlink(dir, name)
		case 3:
			err = os.Symlink(filepath.Join(dir, "nowhere"), name)
		}
		if err != nil {
			t.Skipf("cannot make %s: %v", name, err)
		}
		words = append(words, name)
	}
	type answer struct {
		path           string
		ok             bool
		differ, missed bool
	}
	want := make([]answer, len(words))
	for i, word := range words {
		want[i].path, want[i].ok = ResolveWriteTarget(word)
		want[i].differ, want[i].missed = actionStateEntryMayDiffer(word)
	}
	call0 := NewCallTargetMemo()
	var plain []string // files and missing names: no link to follow
	for evaluation := 0; evaluation < 2; evaluation++ {
		memo := NewTargetMemoIn(call0)
		for i, word := range words {
			path, ok := memo.resolveWriteTarget(word)
			differ, missed := memo.stateEntryMayDiffer(word)
			if got := (answer{path, ok, differ, missed}); got != want[i] {
				t.Fatalf("evaluation %d %s: %+v, fresh reads %+v", evaluation, word, got, want[i])
			}
			if evaluation == 0 && (i%5 == 0 || i%5 == 4) {
				plain = append(plain, word)
			}
		}
	}
	call := NewCallTargetMemo()
	before := workcount.Take()
	for evaluation := 0; evaluation < 2; evaluation++ {
		memo := NewTargetMemoIn(call)
		for _, word := range plain {
			memo.resolveWriteTarget(word)
			memo.stateEntryMayDiffer(word)
		}
	}
	lookups, walks := before.Since(workcount.WordLookup), before.Since(workcount.MemoWalk)
	t.Logf("COUNTED lookups=%d walks=%d words=%d", lookups, walks, len(plain))
	// One Lstat per word, and one per component of the folder for the first.
	bound := int64(len(plain) + strings.Count(dir, string(filepath.Separator)) + 1)
	if lookups > bound {
		t.Fatalf("file lookups = %d for %d words, bound %d (one per word)", lookups, len(plain), bound)
	}
	if walks > int64(len(plain)) {
		t.Fatalf("memo walks = %d for %d words in two evaluations, bound one per word", walks, len(plain))
	}
}
