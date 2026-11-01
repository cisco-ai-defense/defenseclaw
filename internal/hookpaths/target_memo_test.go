// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestTargetMemoWalkAnswersAsAFreshWalk is the exactness proof of the memo
// walk (rel-1-0-2:GAP-0568): resolved through one shared memo, in any order,
// every path answers what a fresh ResolveWriteTarget answers, through
// directory and file links, link chains, a dangling link, a link loop, ".."
// after a link and after a missing component.
func TestTargetMemoWalkAnswersAsAFreshWalk(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "a", "b", "c"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "b", "c", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"la":  "a",
		"lb":  filepath.Join(root, "a", "b"),
		"l1":  "l2",
		"l2":  "l3",
		"l3":  filepath.Join("a", "b", "c"),
		"lf":  filepath.Join("a", "b", "c", "f"),
		"ld":  filepath.Join("missing", "x"),
		"lo1": "lo2",
		"lo2": "lo1",
		"lu":  filepath.Join("a", "b", ".."),
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
	}
	var paths []string
	for _, rel := range []string{
		"a/b/c/f", "a/b/c/new", "la/b/c/f", "la/../a/b", "lb/c/f", "lb/../b/c", "l1/f", "l1/../c",
		"lf", "ld", "ld/../y", "lo1", "lo1/x", "lu/b/c", "missing/../a", "missing/new",
		"a/./b//c/", "a/b/c/f/../f", "la/b/../../la/b", ".", "",
	} {
		paths = append(paths, filepath.Join(root, filepath.FromSlash(rel)))
	}
	// The raw spelling (no Clean) keeps "..", "." and empty components.
	paths = append(paths, root+string(filepath.Separator)+"la"+string(filepath.Separator)+".."+string(filepath.Separator)+"a",
		root+string(filepath.Separator)+"missing"+string(filepath.Separator)+".."+string(filepath.Separator)+"a",
		root+string(filepath.Separator)+"."+string(filepath.Separator)+"a"+string(filepath.Separator)+string(filepath.Separator)+"b")
	type answer struct {
		resolved string
		ok       bool
	}
	want := make(map[string]answer, len(paths))
	for _, path := range paths {
		resolved, ok := ResolveWriteTarget(path)
		want[path] = answer{resolved, ok}
	}
	orders := [][]string{paths, reversed(paths)}
	shuffled := append([]string(nil), paths...)
	random := rand.New(rand.NewPCG(568, 2026))
	random.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	orders = append(orders, shuffled)
	for round, order := range orders {
		memo := NewTargetMemo()
		for pass := 0; pass < 2; pass++ {
			for _, path := range order {
				resolved, ok := memo.resolveWriteTarget(path)
				if got := (answer{resolved, ok}); got != want[path] {
					t.Errorf("order %d pass %d: %s answered %+v through the memo, %+v fresh", round, pass, path, got, want[path])
				}
			}
		}
	}
}

func reversed(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[len(values)-1-i] = value
	}
	return out
}

// gap0568Assignments is a0=1; a1=1; ... a<n-1>=1, the benign form that
// missed the Windows hook window (rel-1-0-2:GAP-0568).
func gap0568Assignments(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("a%d=1", i)
	}
	return strings.Join(parts, "; ")
}

// gap0568Evaluation reads command as the gateway's evaluation does: the
// state scan and both target decisions on the whole call, then again on
// each statement alone (the simple-command passes), all with one memo. It
// returns the memo's file system work.
func gap0568Evaluation(t *testing.T, command, cwd, home string) int {
	t.Helper()
	memo := NewTargetMemo()
	read := func(text string) {
		if memo.ActionStateTargetMention(text, cwd, home) {
			t.Fatalf("%.60q named active state", text)
		}
		if memo.ActionCommandDecisionWithDialectAndGlobFacts(text, cwd, home, actionfacts.DialectPOSIX, nil) != "" ||
			memo.ActionCommandDecisionInShell(text, cwd, home, nil, true) != "" {
			t.Fatalf("%.60q named a protected target", text)
		}
	}
	read(command)
	for _, statement := range strings.Split(command, "; ") {
		read(statement)
	}
	return memo.Work()
}

// TestTargetMemoAssignmentChainWorkIsLinear pins rel-1-0-2:GAP-0568 with a
// work counter, not a clock: an evaluation of a chain of n assignments, the
// whole call and each statement alone, walks each distinct path prefix and
// checks each distinct candidate once, so its work grows linearly in n
// with a small constant. Before the memo every reading and every
// statement pass walked the working directory and the home again for each
// word: on Windows about 70,000 file system calls for 100 statements.
// Both a Windows home read by its spelling and this host's own temporary
// home (the file system walk) are measured.
func TestTargetMemoAssignmentChainWorkIsLinear(t *testing.T) {
	native := t.TempDir()
	if err := os.MkdirAll(filepath.Join(native, "project"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, place := range []struct{ name, home, cwd string }{
		{"windows-spelled", `C:\Users\Alice`, `C:\Users\Alice\project`},
		{"native", native, filepath.Join(native, "project")},
	} {
		t.Run(place.name, func(t *testing.T) {
			work := map[int]int{}
			for _, n := range []int{32, 64, 128} {
				work[n] = gap0568Evaluation(t, gap0568Assignments(n), place.cwd, place.home)
			}
			t.Logf("work: n=32 %d, n=64 %d, n=128 %d", work[32], work[64], work[128])
			if first, second := work[64]-work[32], work[128]-work[64]; second > 2*first+16 {
				t.Errorf("work grew faster than linear: +%d for 32 more statements, then +%d for 64 more", first, second)
			}
			if limit := 8*128 + 256; work[128] > limit {
				t.Errorf("128 statements cost %d units of work, want at most %d (each distinct path and candidate once)", work[128], limit)
			}
		})
	}
}
