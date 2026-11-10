// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import "time"

// MaxStretch is the most Stretch ever reports. A host that keeps a process
// from a third of a CPU or less is overloaded, not slow: a test that needs
// more than this to pass is measuring the host, and its bound fails as it did.
const MaxStretch = 3.0

const (
	// stretchSpins and stretchSpin are the number and wall length of the
	// CPU-bound runs one measurement makes; it keeps the largest result.
	stretchSpins = 3
	stretchSpin  = 150 * time.Millisecond
	// stretchNoise is the ratio of wall time to CPU time below which the host
	// is idle: CPU clocks tick at 15 ms on Windows and a collector may run, so
	// an idle host reads up to about 1.12.
	stretchNoise = 1.25
)

// stretchOf is the factor by which a host stretched a CPU-bound run that took
// wall time and was given cpu time: 1 when there is nothing to name.
func stretchOf(wall, cpu time.Duration) float64 {
	if wall <= 0 || cpu <= 0 {
		return 1
	}
	ratio := float64(wall) / float64(cpu)
	if ratio < stretchNoise {
		return 1
	}
	return min(ratio, MaxStretch)
}

// Stretch measures, now, how much the host stretches the time of a CPU-bound
// run: it spins one goroutine for a short wall time and compares that time
// with the CPU time the process was given (1 on an idle host, at most
// MaxStretch). It takes about half a second, so a test calls it only when a
// bound was missed, through Limit or Within. It names a shortage of CPU and
// nothing else: a product that sleeps, waits for a file or a peer, or blocks
// is not stretched by it, and keeps failing a bound it misses on an idle host.
func Stretch() float64 {
	worst := 1.0
	for range stretchSpins {
		cpuBefore, ok := processCPUTime()
		if !ok {
			return 1
		}
		start := time.Now()
		x := uint64(88172645463325252)
		for time.Since(start) < stretchSpin {
			for range 1 << 12 {
				x ^= x << 13
				x ^= x >> 7
				x ^= x << 17
			}
		}
		wall := time.Since(start)
		if x == 0 { // a xorshift state never reaches 0; the test reads x so the spin stays
			return 1
		}
		cpuAfter, ok := processCPUTime()
		if !ok {
			return 1
		}
		worst = max(worst, stretchOf(wall, cpuAfter-cpuBefore))
	}
	return worst
}

// Limit is bound stretched by what Stretch measures now: the bound itself on
// an idle host.
func Limit(bound time.Duration) time.Duration {
	return time.Duration(float64(bound) * Stretch())
}

// Within reports whether took is inside bound or, when the host is short of
// CPU, inside the bound stretched by Stretch. A took inside bound never
// costs a measurement.
func Within(took, bound time.Duration) bool {
	return took <= bound || took <= Limit(bound)
}
