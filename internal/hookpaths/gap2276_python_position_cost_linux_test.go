// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookpaths

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The python readers ask whether each writer match is executable code. Each
// question read the program from byte 0, so dense python cost the square of
// its size; one resumable reading per program is linear
// (rel-1-0-10:GAP-2276). The cost is the reading's own thread CPU time, the
// cheapest of interleaved batches, so build box load does not move it: 8x the
// code must cost under 24x the time (linear is 8x, 8x to 15x measured with
// the regexp matches; the square is 64x, 41x to 55x measured at the parent).
func TestGAP2276PythonPositionCostIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("cost test")
	}
	shapes := []struct {
		name string
		code func(n int) string
		read func(code string) bool
	}{
		{"writer text in a string", func(n int) string {
			return `x = "` + strings.Repeat("open( ", n) + `"`
		}, func(code string) bool { return actionInterpreterCodeWrites(code, "python") }},
		{"writer calls in code", func(n int) string {
			return strings.Repeat("open(a);", n)
		}, pythonStringWriterText},
		{"reader text in a string", func(n int) string {
			return `k = "~/.ssh/id_ed25519"; x = "` + strings.Repeat("open( ", n) + `"`
		}, func(code string) bool { return actionInterpreterReadsPrivateKey(code, "python") }},
	}
	threadCPU := func() time.Duration {
		var usage unix.Rusage
		if err := unix.Getrusage(unix.RUSAGE_THREAD, &usage); err != nil {
			t.Fatal(err)
		}
		return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
	}
	for _, shape := range shapes {
		small, large := shape.code(250), shape.code(2000)
		if len(large) > 16<<10 {
			t.Fatalf("%s: %d bytes is over the reader limit", shape.name, len(large))
		}
		measure := func(code string, reps int) time.Duration {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			start := threadCPU()
			for i := 0; i < reps; i++ {
				shape.read(code)
			}
			return threadCPU() - start
		}
		best := [2]time.Duration{1 << 62, 1 << 62}
		for batch := 0; batch < 15; batch++ {
			best[0] = min(best[0], measure(small, 64))
			best[1] = min(best[1], measure(large, 8))
		}
		// The large batch has 1/8 of the repetitions of the small one.
		ratio := float64(best[1]) * 8 / float64(best[0])
		t.Logf("%s: %d B %v x64, %d B %v x8: ratio %.1fx", shape.name, len(small), best[0], len(large), best[1], ratio)
		if ratio > 24 {
			t.Errorf("%s: 8x the code costs %.1fx the time, want under 24x (linear)", shape.name, ratio)
		}
	}
}
