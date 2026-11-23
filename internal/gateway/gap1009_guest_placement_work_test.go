// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// gap1009Fit repeats unit (with {k} numbered) between prefix and suffix
// while the script stays within size bytes, and says how many units it holds.
func gap1009Fit(size int, prefix, unit, suffix string) (string, int) {
	var b strings.Builder
	b.WriteString(prefix)
	k := 0
	for ; ; k++ {
		piece := strings.ReplaceAll(unit, "{k}", fmt.Sprint(k))
		if b.Len()+len(piece)+len(suffix) > size {
			break
		}
		b.WriteString(piece)
	}
	b.WriteString(suffix)
	return b.String(), k
}

// TestGAP1009GuestPlacementWorkGrowsAtMostQuadratically pins the work of the
// guest placement on long scripts with many unread commands and function
// declarations, in and out of loops: growing the script from 4 KB to 8 KB
// (the hook cap), r times the repeated units, may cost at most about r*r
// times the span visits. The GAP-0991 loop pass visited every unread command
// for every function and every span (about r*r*r, 131 ms on the 8 KB loop
// where the parent took 6 ms).
func TestGAP1009GuestPlacementWorkGrowsAtMostQuadratically(t *testing.T) {
	nest := func(d int) (string, string) { return strings.Repeat("for i in 1; do ", d), strings.Repeat("done; ", d) }
	o20, c20 := nest(20)
	o100, c100 := nest(100)
	for _, shape := range []struct{ name, prefix, unit, suffix string }{
		{"loop unread+decl", "for i in 1; do ", "$C;f{k}(){ :;};", "done"},
		{"no loop unread+decl", "", "$C;f{k}(){ :;};", "true"},
		{"loop unread, one decl", "for i in 1; do ", "$C;", "g(){ :;}; done"},
		{"loop one unread, decls", "for i in 1; do $C;", "f{k}(){ :;};", "done"},
		{"20 nested loops", o20, "$C;f{k}(){ :;};", c20 + "true"},
		{"100 nested loops", o100, "$C;f{k}(){ :;};", c100 + "true"},
		{"loop decl+call", "for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done"},
		{"loop unread, inner loops", "for i in 1; do ", "$C;for j in 1; do :; done;f{k}(){ :;};", "done"},
	} {
		work, units := map[int]int{}, map[int]int{}
		for _, size := range []int{4095, 8190} {
			command, n := gap1009Fit(size, shape.prefix, shape.unit, shape.suffix)
			visits := 0
			if calls, _ := guestScriptCallsWork(command, "/home/alice", &visits); calls == nil {
				t.Fatalf("%s at %d bytes: no parse", shape.name, size)
			}
			units[size], work[size] = n, visits
		}
		r := float64(units[8190]) / float64(units[4095])
		grew := float64(work[8190]) / float64(work[4095])
		t.Logf("%s: %d -> %d units (r %.2f), %d -> %d visits (%.2f, r*r %.2f)", shape.name, units[4095], units[8190], r, work[4095], work[8190], grew, r*r)
		if r < 1.5 || grew > 1.25*r*r {
			t.Errorf("%s: span visits grew %.2fx for %.2fx the units: more than quadratic", shape.name, grew, r)
		}
	}
}
