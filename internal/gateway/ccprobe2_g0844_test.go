// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0844: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha 92aa1caeb8 lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestCapFloorLatencyStaysNearRel is the GAP-0844 latency guard: a benign
// call past an analysis cap is not judged piece by piece at many times the
// cost of rel (the cap floor judged 16 project-path pieces of a 6 KB &&
// chain as full calls, 13 times rel), and the typical calls stay near rel.
// Times are ratios to a reference call measured in the same loop, so the
// load of the runner cancels out: the long lines within 1.5 times their rel
// ratio, T1-T5 within 1.2 times.
//
// The guard is measured at capFloorLatencyProcs, in separate blocks with a
// collection before each, and a shape fails only when its median block is
// over the bound, that is in at least 3 of the 5 blocks. A real regression
// (2 times rel or more) is over in every block; a pause or a load burst on
// the runner lands in one block (rel-1-0-10:GAP-0896).
func TestCCP2G0844_CapFloorLatencyStaysNearRel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shapes are POSIX shell calls")
	}
	if testing.Short() || hookAnswerRaceBuild {
		t.Skip("a timing guard: not in -short or race builds")
	}
	home, cwd := r104ReviewHome(t)
	request := func(connector, command string) trustedActionRequest {
		return trustedActionRequest{Input: actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
			DialectHint: actionfacts.DialectPOSIX}, Connector: connector, EnforcementCapable: true}
	}
	reference := request("claudecode", "ls -la")
	shapes := ccp2g0844_capFloorLatencyShapes()
	const blocks, rounds = 5, 13
	clock := func(r trustedActionRequest) time.Duration {
		start := time.Now()
		dispatchTrustedAction(t.Context(), r)
		return time.Since(start)
	}
	median := func(d []float64) float64 {
		d = slices.Clone(d)
		slices.Sort(d)
		return d[len(d)/2]
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(ccp2g0844_capFloorLatencyProcs))
	for _, s := range shapes {
		dispatchTrustedAction(t.Context(), request(s.connector, s.command))
	}
	ratios := make([][]float64, len(shapes))
	var refs []float64
	for range blocks {
		runtime.GC()
		timed := make([][]float64, len(shapes))
		var ref []float64
		// Round robin, the reference beside every shape, so a load change on
		// the runner moves both sides of each ratio.
		for range rounds {
			for i, s := range shapes {
				ref = append(ref, float64(clock(reference)))
				timed[i] = append(timed[i], float64(clock(request(s.connector, s.command))))
			}
		}
		refMedian := median(ref)
		refs = append(refs, refMedian)
		for i := range shapes {
			ratios[i] = append(ratios[i], median(timed[i])/refMedian)
		}
	}
	for i, s := range shapes {
		ratio := median(ratios[i])
		bound := 1.2
		if strings.HasPrefix(s.name, "L") {
			bound = 1.5
		}
		rel, recorded := ccp2g0844_capFloorLatencyRel[s.name]
		t.Logf("GAP0844LATENCY %s ratio %.2f blocks %.2f..%.2f bound %.2f rel %.2f reference %.3f ms", s.name,
			ratio, slices.Min(ratios[i]), slices.Max(ratios[i]), bound*rel, rel, median(refs)/1e6)
		if recorded && ratio > bound*rel {
			t.Errorf("%s: %.2f times the reference call in the median of %d blocks, over %.1f times its rel ratio %.2f (rel-1-0-10:GAP-0844)",
				s.name, ratio, blocks, bound, rel)
		}
	}
}

// capFloorLatencyProcs is the GOMAXPROCS the guard measures at, whatever the
// runner sets, so the collector and scheduler share of a run is the one the
// rel ratios were recorded with. Pinned, rel reads the same at GOMAXPROCS 2,
// 4 and 16 (T5 medians 81.6, 81.8, 80.0 on dc-s7-gates); unpinned, one
// GOMAXPROCS=2 run read T5 at 93 (rel-1-0-10:GAP-0896).
const ccp2g0844_capFloorLatencyProcs = 4

// capFloorLatencyRel is each shape's median decision time over the median
// time of the reference call (ls -la), measured on rel/1.0.10 16f68a06f6 with
// this test as it is now (plain build, go1.26.4, GOMAXPROCS pinned to
// capFloorLatencyProcs, median of 5 blocks): the median of 120 runs, count=20
// at GOMAXPROCS 2, 4 and 16 on each of dc-s7-gates and dc-s7-gates2. A rel
// run read at most 1.15 times these values (T2), inside the 1.2 bound. The
// earlier values came from one box and an unpinned single pass (T5 74.5 where
// these boxes read 81), so a correct build could go red (rel-1-0-10:GAP-0896).
//
// Provenance: rel sha 16f68a06f6 (rel code, this test file copied over it),
// testctl TST-3302, dcb-bg jobs g896-lat-rlo (dc-s7-gates) and g896-lat-rl2
// (dc-s7-gates2). The measurement script, the 960 per-run ratios and the
// medians per shape, GOMAXPROCS and box are in testdata/capfloor_latency/
// (measure.sh, rel-runs.tsv, rel-medians.tsv); the rows with box "all" are
// this table. To record again, build rel (16f68a06f6 or 644d23fa3b), never a
// candidate head.
var ccp2g0844_capFloorLatencyRel = map[string]float64{
	"T1-one-file-write": 1.78, "T2-write-4-targets": 10.21, "T3-codex-git-status": 1.10, "T4-benign-read": 1.17,
	"T5-compound-1.5KB": 81.0, "L1-and-chain-6KB": 3.59, "L2-redirects600-9.5KB": 110.2, "L3-list-7KB": 10.59,
}

// capFloorLatencyShapes are the benign calls of the GAP-0844 latency guard:
// the typical calls T1-T5 and the three long lines (a 6 KB && chain, a
// 9.5 KB line of 600 redirects, a 7 KB ; list of writes into the project).
func ccp2g0844_capFloorLatencyShapes() []struct{ name, connector, command string } {
	join := func(sep string, size int, word func(int) string) string {
		var words []string
		for i := 0; len(strings.Join(words, sep)) < size; i++ {
			words = append(words, word(i))
		}
		return strings.Join(words, sep)
	}
	grep := func(i int) string { return fmt.Sprintf("grep -n pattern%d src/file%d.go", i, i) }
	var redirects strings.Builder
	redirects.WriteString("echo hi")
	for i := range 600 {
		fmt.Fprintf(&redirects, " > ordinary/r%d", i)
	}
	return []struct{ name, connector, command string }{
		{"T1-one-file-write", "claudecode", "echo done > notes.txt"},
		{"T2-write-4-targets", "claudecode", "echo a > out1.txt; echo b > out2.txt; echo c > out3.txt; echo d > out4.txt"},
		{"T3-codex-git-status", "codex", "git status"},
		{"T4-benign-read", "claudecode", "cat README.md"},
		{"T5-compound-1.5KB", "claudecode", join(" && ", 1500, grep)},
		{"L1-and-chain-6KB", "claudecode", join(" && ", 6000, grep)},
		{"L2-redirects600-9.5KB", "claudecode", redirects.String()},
		{"L3-list-7KB", "claudecode", join("; ", 7000, func(i int) string { return fmt.Sprintf("echo step%d > build/out%d.txt", i, i) })},
	}
}
