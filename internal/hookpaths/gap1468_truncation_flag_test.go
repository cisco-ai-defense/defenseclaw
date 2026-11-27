// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// pathReadDirLimit returns the first n entries of the whole directory by
// name, for every size around n and past the 2n it holds at a time.
func TestGAP1468PathReadDirLimitIsTheSortedPrefix(t *testing.T) {
	const n = 10
	for _, size := range []int{0, 1, n - 1, n, n + 1, 2 * n, 2*n + 1, 3000} {
		dir := t.TempDir()
		for index := 0; index < size; index++ {
			// Names in an order that is neither creation nor name order.
			name := fmt.Sprintf("e%05d", (index*7919)%size)
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		all, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		want := all[:min(n, len(all))]
		got, err := pathReadDirLimit(dir, n)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		names := func(entries []os.DirEntry) []string {
			out := make([]string, len(entries))
			for index, entry := range entries {
				out[index] = entry.Name()
			}
			return out
		}
		if !slices.Equal(names(got), names(want)) {
			t.Errorf("size %d: got %v, want the sorted prefix %v", size, names(got), names(want))
		}
	}
}

// A registration reader that decides on the matches read before the cap,
// none of them registered, reports the cap: the caller judges the reading at
// least at the unknown tier (the one bound rule). A pattern over a directory
// under the cap reports none, and a reader that found a registered file
// before the cap still reaches it (rel-1-0-10:GAP-1468).
func TestGAP1468RegistrationReadersKeepTheTruncation(t *testing.T) {
	home := t.TempDir()
	registered := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(registered), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registered, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wide, first := gap1468WideDir(t, func(path string) error { return os.WriteFile(path, nil, 0o644) })
	small := t.TempDir()
	for index := 0; index < 20; index++ {
		if err := os.WriteFile(filepath.Join(small, fmt.Sprintf("f%02d", index)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		command   string
		names     []string
		reached   bool
		truncated bool
	}{
		{"rm -f " + wide + "/zz*", []string{registered}, false, true},
		{"for f in " + wide + "/zz*; do rm -f \"$f\"; done", []string{registered}, false, true},
		{"rm -f " + small + "/zz*", []string{registered}, false, false},
		{"for f in " + small + "/f*; do rm -f \"$f\"; done", []string{registered}, false, false},
		{"rm -f " + wide + "/0first*", []string{filepath.Join(wide, first)}, true, false},
	} {
		reached, truncated := RegistrationWriteReachedBounded(row.command, home, home, row.names, nil)
		if got := len(reached) != 0; got != row.reached {
			t.Errorf("%q: reached %q, want reached=%v", row.command, reached, row.reached)
		}
		if row.truncated && !truncated.Has(bounded.Paths) || !row.truncated && truncated.Any() && !row.reached {
			t.Errorf("%q: truncated %q, want truncated=%v", row.command, truncated.Reason(), row.truncated)
		}
		if row.truncated && !strings.Contains(truncated.Reason(), "paths") {
			t.Errorf("%q: reason %q, want the paths cap", row.command, truncated.Reason())
		}
	}
}
