// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// The generated property tests of the passthrough proxy run a bounded,
// deterministic sample by default and the whole sweep on an explicit opt-in.
//
// A sweep over every wire x probe x shape x stream x mode takes minutes on a
// CI runner, and the planner cannot split one test. The sample is a pairwise
// covering one: from the whole cross product it picks, greedily and with a
// fixed seed, the fewest combinations that still cover every value of every
// dimension and every pair of values of the dimensions the test names, at
// least once. Every class is therefore hit; only the high-order combinations
// are left to the full sweep. The same input gives the same sample, on any
// host. DEFENSECLAW_PROPERTY_FULL=1 runs everything.

// covPropertyFullEnv is the opt-in of the full sweep.
const covPropertyFullEnv = "DEFENSECLAW_PROPERTY_FULL"

func covPropertyFull() bool { return os.Getenv(covPropertyFullEnv) == "1" }

// covSample returns the combinations a property test runs: one index per
// dimension of dims (dims[i] is the number of values of dimension i, names[i]
// its name for the log). valid, when set, drops combinations that do not exist
// (a slot a wire does not have). pairs decides which pairs of dimensions must
// be covered in full; nil means all pairs. In the full mode it returns every
// valid combination. The log gives the combinations chosen and, per dimension,
// how many times each value is run.
func covSample(t *testing.T, test string, names []string, dims []int, valid func(c []int) bool, pairs func(a, b int) bool) [][]int {
	t.Helper()
	var all [][]int
	cur := make([]int, len(dims))
	var gen func(i int)
	gen = func(i int) {
		if i == len(dims) {
			if valid == nil || valid(cur) {
				all = append(all, append([]int(nil), cur...))
			}
			return
		}
		for v := 0; v < dims[i]; v++ {
			cur[i] = v
			gen(i + 1)
		}
	}
	gen(0)

	chosen := all
	if !covPropertyFull() {
		chosen = covPairwise(test, dims, all, pairs)
	}

	counts := make([][]int, len(dims))
	for i := range dims {
		counts[i] = make([]int, dims[i])
	}
	for _, c := range chosen {
		for i, v := range c {
			counts[i][v]++
		}
	}
	var sb strings.Builder
	for i, n := range names {
		fmt.Fprintf(&sb, " %s=%v", n, counts[i])
	}
	mode := "sample (" + covPropertyFullEnv + "=1 runs every combination)"
	if covPropertyFull() {
		mode = "full sweep"
	}
	t.Logf("%s: %s: %d of %d combinations; runs per value:%s", test, mode, len(chosen), len(all), sb.String())
	return chosen
}

// covPairwise picks the covering sample: every value of every dimension and
// every pair of values the pairs function asks for appear in at least one
// chosen combination. Greedy, deterministic (the order of the candidates is a
// shuffle seeded by the test name).
func covPairwise(test string, dims []int, all [][]int, pairs func(a, b int) bool) [][]int {
	h := fnv.New64a()
	_, _ = h.Write([]byte(test))
	rnd := rand.New(rand.NewSource(int64(h.Sum64())))
	order := rnd.Perm(len(all))

	type key struct{ a, b, va, vb int }
	covered := map[key]bool{}
	seenVal := map[[2]int]bool{}
	var keys func(c []int) (vals [][2]int, prs []key)
	keys = func(c []int) ([][2]int, []key) {
		var vals [][2]int
		var prs []key
		for i := range c {
			vals = append(vals, [2]int{i, c[i]})
			for j := i + 1; j < len(c); j++ {
				if pairs == nil || pairs(i, j) {
					prs = append(prs, key{i, j, c[i], c[j]})
				}
			}
		}
		return vals, prs
	}
	// What has to be covered: the values and the pairs that occur in a valid
	// combination.
	need := map[key]bool{}
	needVal := map[[2]int]bool{}
	for _, c := range all {
		vals, prs := keys(c)
		for _, v := range vals {
			needVal[v] = true
		}
		for _, p := range prs {
			need[p] = true
		}
	}
	var out [][]int
	for len(covered) < len(need) || len(seenVal) < len(needVal) {
		best, bestGain := -1, 0
		for _, oi := range order {
			vals, prs := keys(all[oi])
			gain := 0
			for _, v := range vals {
				if !seenVal[v] {
					gain++
				}
			}
			for _, p := range prs {
				if !covered[p] {
					gain++
				}
			}
			if gain > bestGain {
				best, bestGain = oi, gain
			}
		}
		if best < 0 {
			break
		}
		vals, prs := keys(all[best])
		for _, v := range vals {
			seenVal[v] = true
		}
		for _, p := range prs {
			covered[p] = true
		}
		out = append(out, all[best])
	}
	return out
}

// covCutPoints are the offsets at which a test splits a stream of frames: all
// of them in the full mode; otherwise the neighbourhood of every frame
// boundary (the places a split is easy to get wrong) and a stride through the
// rest.
func covCutPoints(frames [][]byte) []int {
	total := 0
	for _, f := range frames {
		total += len(f)
	}
	if covPropertyFull() {
		out := make([]int, 0, total)
		for c := 1; c < total; c++ {
			out = append(out, c)
		}
		return out
	}
	set := map[int]bool{}
	off := 0
	for _, f := range frames {
		for d := -2; d <= 2; d++ {
			set[off+d] = true
		}
		set[off+len(f)/2] = true
		off += len(f)
		for d := -2; d <= 2; d++ {
			set[off+d] = true
		}
	}
	for c := 7; c < total; c += 53 {
		set[c] = true
	}
	var out []int
	for c := 1; c < total; c++ {
		if set[c] {
			out = append(out, c)
		}
	}
	return out
}

// covPick returns whether a combination of indices is in the sample.
func covPick(sample [][]int) func(idx ...int) bool {
	set := make(map[string]bool, len(sample))
	for _, c := range sample {
		set[fmt.Sprint(c)] = true
	}
	return func(idx ...int) bool { return set[fmt.Sprint(idx)] }
}

// The sample is deterministic and covers every value of every dimension and
// every pair the test asks for; the full mode returns everything.
func TestCovSampleCoversEveryClassDeterministically(t *testing.T) {
	dims := []int{2, 3, 5, 10, 2}
	names := []string{"mode", "wire", "probe", "shape", "stream"}
	noProbeShape := func(a, b int) bool { return !(a == 2 && b == 3) }
	valid := func(c []int) bool { return !(c[0] == 0 && c[3] == 9) } // a combination that does not exist
	a := covSample(t, "unit", names, dims, valid, noProbeShape)
	b := covSample(t, "unit", names, dims, valid, noProbeShape)
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatal("the sample is not deterministic")
	}
	if len(a) >= 600 || len(a) < 30 {
		t.Fatalf("%d combinations in the sample", len(a))
	}
	type pk struct{ i, j, x, y int }
	seen := map[pk]bool{}
	vals := map[[2]int]bool{}
	for _, c := range a {
		if !valid(c) {
			t.Fatalf("%v is not a valid combination", c)
		}
		for i := range c {
			vals[[2]int{i, c[i]}] = true
			for j := i + 1; j < len(c); j++ {
				seen[pk{i, j, c[i], c[j]}] = true
			}
		}
	}
	for i, n := range dims {
		for v := 0; v < n; v++ {
			if !vals[[2]int{i, v}] {
				t.Errorf("value %d of %s is never run", v, names[i])
			}
		}
		for j := i + 1; j < len(dims); j++ {
			if !noProbeShape(i, j) {
				continue
			}
			for x := 0; x < n; x++ {
				for y := 0; y < dims[j]; y++ {
					if valid(append(make([]int, 0), comboWith(dims, i, x, j, y)...)) && !seen[pk{i, j, x, y}] {
						// A pair that occurs in some valid combination must be run.
						if pairOccurs(dims, valid, i, x, j, y) {
							t.Errorf("pair %s=%d %s=%d is never run", names[i], x, names[j], y)
						}
					}
				}
			}
		}
	}
	t.Setenv(covPropertyFullEnv, "1")
	if all := covSample(t, "unit", names, dims, valid, noProbeShape); len(all) != 600-30 {
		t.Errorf("the full mode returned %d combinations, want 570", len(all))
	}
}

func comboWith(dims []int, i, x, j, y int) []int {
	c := make([]int, len(dims))
	c[i], c[j] = x, y
	return c
}

func pairOccurs(dims []int, valid func([]int) bool, i, x, j, y int) bool {
	cur := make([]int, len(dims))
	var rec func(k int) bool
	rec = func(k int) bool {
		if k == len(dims) {
			return valid(cur)
		}
		for v := 0; v < dims[k]; v++ {
			if (k == i && v != x) || (k == j && v != y) {
				continue
			}
			cur[k] = v
			if rec(k + 1) {
				return true
			}
		}
		return false
	}
	return rec(0)
}

// The cut points keep the neighbourhood of every frame boundary.
func TestCovCutPoints(t *testing.T) {
	frames := [][]byte{make([]byte, 100), make([]byte, 80), make([]byte, 120)}
	cuts := covCutPoints(frames)
	has := map[int]bool{}
	for _, c := range cuts {
		has[c] = true
	}
	for _, b := range []int{100, 180} {
		for d := -2; d <= 2; d++ {
			if !has[b+d] {
				t.Errorf("no cut at %d, next to the frame boundary %d", b+d, b)
			}
		}
	}
	if len(cuts) >= 299 {
		t.Errorf("%d cuts, the sample is not smaller than the sweep", len(cuts))
	}
	t.Setenv(covPropertyFullEnv, "1")
	if len(covCutPoints(frames)) != 299 {
		t.Errorf("the full mode must cut at every offset")
	}
}
