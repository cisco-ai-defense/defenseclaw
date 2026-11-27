//go:build linux && !race

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"strings"
	"syscall"
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

// gap2230ThreadCPU is the CPU time of the calling thread (RUSAGE_THREAD):
// what the reading costs itself, not the time other processes on the box
// take from it.
func gap2230ThreadCPU(t *testing.T) time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(1 /* RUSAGE_THREAD */, &usage); err != nil {
		t.Fatalf("getrusage: %v", err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

// gap2230CostRatio is the CPU cost of one reading of large over one of
// small on one locked thread: batches of at least 40 ms of CPU each, a
// collection before each batch, the two sizes read back to back in each of
// 15 rounds, the cheapest batch per size (sharing a core only adds CPU
// time). Wall clock under build box
// load (the fastest of 9 single readings per size) moved from 10x to 16.6x
// on one commit, and a median of wall-clock rounds still crossed 11x once
// in four runs at load 31.
func gap2230CostRatio(t *testing.T, small, large, language string) (float64, time.Duration, time.Duration) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	read := func(code string) { _ = literalInterpreterWrites(code, language, "/tmp", "/tmp") }
	repeats := func(code string) int {
		start := gap2230ThreadCPU(t)
		read(code)
		read(code)
		return max(1, int(40*time.Millisecond/max(gap2230ThreadCPU(t)-start, time.Microsecond)))
	}
	batch := func(code string, n int) time.Duration {
		runtime.GC()
		start := gap2230ThreadCPU(t)
		for range n {
			read(code)
		}
		return max((gap2230ThreadCPU(t)-start)/time.Duration(n), time.Nanosecond)
	}
	nSmall, nLarge := repeats(small), repeats(large)
	smallCost, largeCost := time.Duration(1<<62), time.Duration(1<<62)
	for range 15 {
		smallCost, largeCost = min(smallCost, batch(small, nSmall)), min(largeCost, batch(large, nLarge))
	}
	return float64(largeCost) / float64(smallCost), smallCost, largeCost
}

// TestGAP2230PerlDenseCostIsLinear: the reader's cost on token-dense code
// grows with its size, not its square. Before GAP-2230 a statement of an
// assignment and an open per 18 bytes took 21x as long at 16 KiB as at 2 KiB
// (8x is linear), assignments then opens 15x, and requires then sysopens
// read the rest of the program once per require. Every writer call of the
// shared reader read the program from its first byte to know whether the
// call is code (literalCodePosition), in every language.
func TestGAP2230PerlDenseCostIsLinear(t *testing.T) {
	shapes := []struct{ id, language, front, back string }{
		{"assign-open", "perl", "$m='>';open(F,$m,'a');", ""},
		{"assigns-then-opens", "perl", "$m='>';", "open(F,$m,'a');"},
		{"flag-assigns-then-sysopens", "perl", "$f=O_WRONLY;", "sysopen(F,'a',$f);"},
		{"requires-then-sysopens", "perl", "require Fcntl;", "sysopen(F,'a',O_WRONLY);"},
		{"loop-words", "perl", " for 1", ""},
		{"python-opens", "python", "open('a','w')\n", ""},
		{"node-writes", "node", "fs.writeFileSync('a','x');", ""},
	}
	for _, shape := range shapes {
		ratio, small, large := gap2230CostRatio(t, gap2230Dense(shape.front, shape.back, 2<<10-1),
			gap2230Dense(shape.front, shape.back, 16<<10-1), shape.language)
		t.Logf("%s: 2 KiB %v CPU, 16 KiB %v CPU, %.1fx", shape.id, small, large, ratio)
		if ratio > 11 {
			t.Errorf("%s: 16 KiB costs %.1fx of 2 KiB (8x is linear), want at most 11x", shape.id, ratio)
		}
	}
}
