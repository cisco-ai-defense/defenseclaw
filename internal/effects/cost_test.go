// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
	"time"
)

// TestNestedSubstitutionIsBounded guards the hot path against the round-3 DoS:
// deeply nested $( ), <( ), PowerShell $( ) and & { } must not do exponential
// work (review R3-1). Wall-clock time moves 1.5x with machine load, so the test
// counts allocations instead -- they are identical quiet and loaded:
//
//   - the allocations of each shape at depth 64 stay under a fixed ceiling;
//   - the allocations grow linearly with depth (allocs(200) / allocs(64) < 4, where
//     3.1x is the linear ratio and an exponential walk is orders higher);
//   - a flat 100 KB word allocates a bounded amount;
//   - a loose 2 s wall-clock backstop catches a true hang only.
func TestNestedSubstitutionIsBounded(t *testing.T) {
	nest := func(open, close, mid string, d int) string {
		return strings.Repeat(open, d) + mid + strings.Repeat(close, d)
	}
	type shape struct {
		name    string
		o       Options
		mk      func(d int) string
		ceiling float64 // allocations at depth 64 (about 2x the measured value)
	}
	shapes := []shape{
		{"posix cmdsubst", envOpts, func(d int) string { return "echo " + nest("$(echo ", ")", "x", d) }, 3000},
		{"posix cmdsubst dq", envOpts, func(d int) string { return "echo " + nest(`"$(echo `, `)"`, "x", d) }, 3200},
		{"posix procsubst", envOpts, func(d int) string { return nest("cat <(", ")", "rm a", d) }, 3000},
		{"posix cmdsubst rm", envOpts, func(d int) string { return nest("$(", ")", "rm a", d) }, 3000},
		{"ps subexpr", winPS, func(d int) string { return "Write-Output " + nest("$(Write-Output ", ")", "x", d) }, 4000},
		{"ps scriptblock", winPS, func(d int) string { return nest("& { ", " }", "Remove-Item a", d) }, 3000},
	}
	allocs := func(o Options, cmd string) float64 {
		return testing.AllocsPerRun(5, func() { _ = Extract(sh(cmd), o) })
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			a64, a200 := allocs(s.o, s.mk(64)), allocs(s.o, s.mk(200))
			if a64 > s.ceiling {
				t.Errorf("depth 64 allocates %.0f (> %.0f): nested work grew", a64, s.ceiling)
			}
			if a64 > 0 && a200/a64 >= 4 {
				t.Errorf("allocations grow faster than linearly: depth 64 = %.0f, depth 200 = %.0f (ratio %.2f, linear is 3.1)", a64, a200, a200/a64)
			}
			start := time.Now()
			_ = Extract(sh(s.mk(200)), s.o)
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("depth 200 took %v: the walk hung", d)
			}
		})
	}
	t.Run("posix 100kb nested word", func(t *testing.T) {
		cmd := "cat " + strings.Repeat("a", 100000)
		if a := allocs(envOpts, cmd); a > 400 {
			t.Errorf("a flat 100 KB word allocates %.0f (> 400)", a)
		}
		start := time.Now()
		_ = Extract(sh(cmd), envOpts)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("a 100 KB word took %v", d)
		}
	})
}
