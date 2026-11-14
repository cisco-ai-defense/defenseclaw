// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A misused bounded.Counter panics in this package's tests (TestAdopters).
func init() { bounded.PanicOnMisuse(true) }

// rel-1-0-10:GAP-0401: the one pattern walk (actionExpandGlob, the GAP-0018
// chunked read) reports its bounds through internal/guardrail/bounded: past
// the directory-read bound it hit cap paths, past the name bound cap items,
// and every name read before the cap is still matched. At the bound it is
// complete; the default bounds read a busy folder in full.
func TestGAP0401GlobWalkCapsAreBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX folders")
	}
	if actionGlobMaxReads.Load() != 64 || actionGlobMaxEntries.Load() != 1<<18 {
		t.Fatalf("default bounds %d reads, %d names; the gateway lane registration pins 64 reads",
			actionGlobMaxReads.Load(), actionGlobMaxEntries.Load())
	}
	expand := func(pattern string) ([]string, bool, bounded.CapSet) {
		candidates, complete, _, caps := actionExpandGlobBounded(pattern, "", false, true, func() bool { return false }, false)
		return candidates, complete, caps
	}
	names := t.TempDir()
	fillDir(t, names, 64)
	busy := t.TempDir()
	fillDir(t, busy, actionGlobMaxNames+1)
	dirs := t.TempDir()
	for i := range 70 {
		if err := os.Mkdir(filepath.Join(dirs, fmt.Sprintf("d%02d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if got, complete, caps := expand(filepath.Join(busy, "*")); !complete || caps.Any() || len(got) != actionGlobMaxNames+1 {
		t.Fatalf("default bounds, busy folder: %d names, complete %t, caps %q", len(got), complete, caps.Reason())
	}
	defer UseGlobWalkBoundsForTests(64, 64)()
	if got, complete, caps := expand(filepath.Join(names, "*")); !complete || caps.Any() || len(got) != 64 {
		t.Fatalf("at the name bound: %d names, complete %t, caps %q", len(got), complete, caps.Reason())
	}
	fillDir(t, names, 100)
	if got, complete, caps := expand(filepath.Join(names, "*")); complete || !caps.Has(bounded.Items) || len(got) != 100 {
		t.Fatalf("past the name bound: %d names (want all read names), complete %t, caps %q", len(got), complete, caps.Reason())
	}
	if _, complete, caps := expand(filepath.Join(dirs, "*", "*")); complete || !caps.Has(bounded.Paths) {
		t.Fatalf("past the read bound: complete %t, caps %q", complete, caps.Reason())
	}
}
