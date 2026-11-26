//go:build !race

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
	"time"
)

// gap2230Dense is token-dense benign Perl of size bytes: front repeated over
// the first half and back over the rest (back empty: front all the way).
func gap2230Dense(front, back string, size int) string {
	if back == "" {
		return strings.Repeat(front, size/len(front))
	}
	half := strings.Repeat(front, size/2/len(front))
	return half + strings.Repeat(back, (size-len(half))/len(back))
}

func gap2230Fastest(code string) time.Duration {
	best := time.Duration(1 << 62)
	for range 9 {
		start := time.Now()
		_ = literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
		best = min(best, time.Since(start))
	}
	return best
}

// TestGAP2230PerlDenseCostIsLinear: the reader's cost on token-dense code
// grows with its size, not its square. Before GAP-2230 a statement of an
// assignment and an open per 18 bytes took 21x as long at 16 KiB as at 2 KiB
// (8x is linear), assignments then opens 15x, and requires then sysopens
// read the rest of the program once per require.
func TestGAP2230PerlDenseCostIsLinear(t *testing.T) {
	shapes := []struct{ id, front, back string }{
		{"assign-open", "$m='>';open(F,$m,'a');", ""},
		{"assigns-then-opens", "$m='>';", "open(F,$m,'a');"},
		{"flag-assigns-then-sysopens", "$f=O_WRONLY;", "sysopen(F,'a',$f);"},
		{"requires-then-sysopens", "require Fcntl;", "sysopen(F,'a',O_WRONLY);"},
		{"loop-words", " for 1", ""},
	}
	for _, shape := range shapes {
		small := gap2230Fastest(gap2230Dense(shape.front, shape.back, 2<<10-1))
		large := gap2230Fastest(gap2230Dense(shape.front, shape.back, 16<<10-1))
		ratio := float64(large) / float64(max(small, time.Microsecond))
		t.Logf("%s: 2 KiB %v, 16 KiB %v, %.1fx", shape.id, small, large, ratio)
		if ratio > 11 {
			t.Errorf("%s: 16 KiB costs %.1fx of 2 KiB (8x is linear), want at most 11x", shape.id, ratio)
		}
	}
}
