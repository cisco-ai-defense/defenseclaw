package psparse

import (
	"strings"
	"testing"
	"time"
)

// TestNoSuperlinearBlowup guards against pathological parse times on adversarial
// deeply-nested or long inputs (a hook-path DoS risk). Each must finish well
// under the hook answer window.
func TestNoSuperlinearBlowup(t *testing.T) {
	n := 4000
	cases := map[string]string{
		"subexpr": strings.Repeat("$(", n),
		"hash":    strings.Repeat("@{", n),
		"paren":   strings.Repeat("(", n),
		"brace":   strings.Repeat("{", n),
		"bracket": strings.Repeat("[", n),
		"array":   strings.Repeat("@(", n),
		"amp":     strings.Repeat("& ", n) + "x",
		"pipe":    strings.Repeat("a|", n) + "b",
		"comma":   "x " + strings.Repeat("a,", n) + "b",
		"dollar":  strings.Repeat("${`", n),
	}
	for name, src := range cases {
		start := time.Now()
		_ = Project(mustParse(src, DialectPwsh7))
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("%s: %v (too slow, len=%d)", name, d, len(src))
		}
	}
}

// nestedStringSrc builds a deeply nested "$( ... )" expandable string.
func nestedStringSrc(depth int) string {
	var b strings.Builder
	b.WriteString("Write-Output ")
	for i := 0; i < depth; i++ {
		b.WriteString(`"$(`)
	}
	b.WriteString("x")
	for i := 0; i < depth; i++ {
		b.WriteString(`)"`)
	}
	return b.String()
}

// TestNestedStringScaling guards F12: nested "$( ... )" inside expandable
// strings must stay near-linear. It asserts scaling, not an absolute time, so
// a loaded box or the race detector cannot make it flake (review 7 R7-4): the
// cost of a 4x larger input is compared with the cost of the base input, and
// a linear parser lands near 4x while the former quadratic one lands near 16x.
// Allocations are the deterministic check; the best of several timed runs is a
// coarse second check with a wide margin.
func TestNestedStringScaling(t *testing.T) {
	run := func(depth int) {
		sc, _ := Parse(nestedStringSrc(depth), Options{})
		_ = Project(sc)
		_ = ExtractNestedScripts(sc)
	}
	const base, big = 5000, 20000 // big is ~100 KB of source
	allocSmall := testing.AllocsPerRun(1, func() { run(base) })
	allocBig := testing.AllocsPerRun(1, func() { run(big) })
	if allocSmall > 0 && allocBig/allocSmall > 6 {
		t.Errorf("allocations grew %.1fx for a 4x larger input (%.0f -> %.0f); want ~4x (possible super-linear blowup)",
			allocBig/allocSmall, allocSmall, allocBig)
	}
	best := func(depth int) time.Duration {
		min := time.Duration(1<<63 - 1)
		for i := 0; i < 5; i++ {
			start := time.Now()
			run(depth)
			if d := time.Since(start); d < min {
				min = d
			}
		}
		return min
	}
	tSmall, tBig := best(base), best(big)
	if tSmall > 0 && float64(tBig)/float64(tSmall) > 12 {
		t.Errorf("time grew %.1fx for a 4x larger input (%v -> %v); want ~4x (possible super-linear blowup)",
			float64(tBig)/float64(tSmall), tSmall, tBig)
	}
}
