// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// linearReaderHookBudget is the documented tool-call hook wait (about 3.5 s):
// a linear reader still judges a large crafted command inside it.
const linearReaderHookBudget = 3500 * time.Millisecond

// startWork starts timing one piece of work and returns the function that
// ends it. The time is the wall time or, when the process used less CPU than
// that, the CPU it used: a host that is busy with other programs makes a
// reading wait for a CPU, and that wait is the host's, not the reading's
// (GAP-0859). On an idle host the two are the same, so the ceiling and the
// size ratio mean what they meant; a reading that costs more CPU, or grows
// faster than its input, still fails them.
func startWork() func() time.Duration {
	wall := time.Now()
	cpu, cpuKnown := processCPUTime()
	return func() time.Duration {
		took := time.Since(wall)
		if now, ok := processCPUTime(); cpuKnown && ok && now-cpu < took {
			took = now - cpu
		}
		return took
	}
}

// assertLinearReaderTime is the time check of the reader linear-time tests
// (rel-1-0-4 GAP-2545, LEAD 11:52 ruling). full is the time of the full-size
// input; run(false) judges the half-size input and run(true) the full one
// again. The full size must take at most 2.5x the half size (best of up to
// 3 tries, 50 ms for timer noise), so the reading grows linearly; a quadratic
// reading takes 4x. Outside -race the full size must also stay within the
// hook budget (best of up to 3 runs); -race costs about 10x and hosted runners vary, so a single
// wall-clock figure is no pass criterion there.
func assertLinearReaderTime(t *testing.T, label string, full time.Duration, run func(full bool) time.Duration) {
	t.Helper()
	assertLinearReaderTimeWith(t, label, full, run, true)
}

// assertLinearReaderTimeWith is assertLinearReaderTime; without ceiling the
// hook-budget time is logged, not failed (a case with an open product row).
func assertLinearReaderTimeWith(t *testing.T, label string, full time.Duration, run func(full bool) time.Duration, ceiling bool) {
	t.Helper()
	bestFull, bestHalf := full, time.Duration(-1)
	linear := func() bool { return bestFull <= bestHalf*5/2+50*time.Millisecond }
	for try := 0; try < 3; try++ {
		if half := run(false); bestHalf < 0 || half < bestHalf {
			bestHalf = half
		}
		if try > 0 {
			if again := run(true); again < bestFull {
				bestFull = again
			}
		}
		if linear() {
			break
		}
	}
	for try := 1; !hookAnswerRaceBuild && bestFull > linearReaderHookBudget && try < 3; try++ {
		if again := run(true); again < bestFull {
			bestFull = again
		}
	}
	t.Logf("%s: full size %s, half size %s", label, bestFull, bestHalf)
	if !linear() {
		t.Errorf("%s: full size %s, half size %s: not linear (over 2.5x)", label, bestFull, bestHalf)
	}
	if !hookAnswerRaceBuild && bestFull > linearReaderHookBudget && !ceiling {
		t.Logf("%s: full size judged in %s, over the %s hook budget (known, not failed here)", label, bestFull, linearReaderHookBudget)
	} else if !hookAnswerRaceBuild && bestFull > linearReaderHookBudget {
		t.Errorf("%s: full size judged in %s, over the %s hook budget", label, bestFull, linearReaderHookBudget)
	}
}
