// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// capFloorLatencyShapes are the benign calls of the GAP-0844 latency guard:
// the typical calls T1-T5 and the three long lines (a 6 KB && chain, a
// 9.5 KB line of 600 redirects, a 7 KB ; list of writes into the project).
func capFloorLatencyShapes() []struct{ name, connector, command string } {
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

// capFloorLatencyRel is each shape's median decision time over the median
// time of the reference call (ls -la), measured on rel/1.0.10 16f68a06f6
// with this test (plain build, GOMAXPROCS=4, dc-s7-bench2, mean of 5 runs at
// load 40 to 65, GAP-0844).
var capFloorLatencyRel = map[string]float64{
	"T1-one-file-write": 1.83, "T2-write-4-targets": 9.74, "T3-codex-git-status": 1.07, "T4-benign-read": 1.12,
	"T5-compound-1.5KB": 74.5, "L1-and-chain-6KB": 3.55, "L2-redirects600-9.5KB": 103.3, "L3-list-7KB": 11.0,
}

// TestCapFloorLatencyStaysNearRel is the GAP-0844 latency guard: a benign
// call past an analysis cap is not judged piece by piece at many times the
// cost of rel (the cap floor judged 16 project-path pieces of a 6 KB &&
// chain as full calls, 13 times rel), and the typical calls stay near rel.
// Times are ratios to a reference call measured in the same loop, so the
// load of the runner cancels out: the long lines within 1.5 times their rel
// ratio, T1-T5 within 1.2 times.
func TestCapFloorLatencyStaysNearRel(t *testing.T) {
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
	shapes := capFloorLatencyShapes()
	const rounds = 41
	timed := make([][]time.Duration, len(shapes))
	var ref []time.Duration
	clock := func(r trustedActionRequest) time.Duration {
		start := time.Now()
		dispatchTrustedAction(t.Context(), r)
		return time.Since(start)
	}
	for _, s := range shapes {
		dispatchTrustedAction(t.Context(), request(s.connector, s.command))
	}
	// Round robin, the reference beside every shape, so a load change on
	// the runner moves both sides of each ratio.
	for range rounds {
		for i, s := range shapes {
			ref = append(ref, clock(reference))
			timed[i] = append(timed[i], clock(request(s.connector, s.command)))
		}
	}
	median := func(d []time.Duration) float64 {
		d = slices.Clone(d)
		slices.Sort(d)
		return float64(d[len(d)/2])
	}
	refMedian := median(ref)
	for i, s := range shapes {
		ratio := median(timed[i]) / refMedian
		bound := 1.2
		if strings.HasPrefix(s.name, "L") {
			bound = 1.5
		}
		rel, recorded := capFloorLatencyRel[s.name]
		t.Logf("GAP0844LATENCY %s p50 %.3f ms reference %.3f ms ratio %.2f rel %.2f", s.name,
			median(timed[i])/1e6, refMedian/1e6, ratio, rel)
		if recorded && ratio > bound*rel {
			t.Errorf("%s: %.2f times the reference call, over %.1f times its rel ratio %.2f (rel-1-0-10:GAP-0844)",
				s.name, ratio, bound, rel)
		}
	}
}
