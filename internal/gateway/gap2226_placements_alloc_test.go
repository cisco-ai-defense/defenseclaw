// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap2226RdDyn6460 is rd-dyn-64-60 of the rel-1-0-10:GAP-2226 cost probe:
// a cd, an unread command, 64 cd-and-list pairs and 60 touches.
func gap2226RdDyn6460() string {
	var b strings.Builder
	b.WriteString("cd .cache\n$CMD\n")
	for i := range 64 {
		fmt.Fprintf(&b, "cd /tmp/rk4r%d && ls\n", i)
	}
	for i := range 60 {
		fmt.Fprintf(&b, "touch f%d\n", i)
	}
	b.WriteString("ls")
	return b.String()
}

// TestGAP2226PlacementsAreMadeAtTheListsSize pins the memory the guest
// placement takes on rd-dyn-64-60 (6,113 and 8,128 readings): its
// placements and seen grew a reading at a time and each pass copied its
// lists twice, 5.34 and 8.18 MB at 1f03087b20, 2.96 and 4.76 MB made at
// the lists' size (dc-build-1). The shape's actor was the one the 1.0.11
// candidate made slower than its parent (rel-1-0-10:GAP-2226). The
// readings themselves are the parent pass's (TestGAP2249CallPassIsTheParentPass).
func TestGAP2226PlacementsAreMadeAtTheListsSize(t *testing.T) {
	bounds := map[bool]float64{true: 4.0, false: 6.4}
	input := actionfacts.Input{Tool: "Bash", Command: gap2226RdDyn6460(), CWD: sandboxauth.SandboxHome, ActiveHome: sandboxauth.SandboxHome}
	plan := new(guestReadingMemo).plan(input, actionfacts.Analyze(input))
	for _, budget := range []bool{true, false} {
		placements, _ := plan.placements(budget) // warm
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		plan.placements(budget)
		runtime.ReadMemStats(&after)
		megabytes := float64(after.TotalAlloc-before.TotalAlloc) / 1e6
		t.Logf("budget %v: %d readings, %.2f MB, %d allocations", budget, len(placements), megabytes, after.Mallocs-before.Mallocs)
		if len(placements) < 6000 {
			t.Fatalf("budget %v: %d readings, want the shape's 6,000 or more", budget, len(placements))
		}
		if megabytes > bounds[budget] {
			t.Errorf("budget %v: the guest placement allocated %.2f MB, over %.1f MB (rel-1-0-10:GAP-2226)", budget, megabytes, bounds[budget])
		}
	}
}
