// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"fmt"
	"sort"
	"time"
)

// HoldRuns is how many times HoldsUnderBar measures a leg before it fails it.
const HoldRuns = 3

// HoldsUnderBar judges one timing leg of many short holds (the time a lock is
// held across n passes) against a smoke bar, for a host that shares its disk
// and CPU with other test runs. One slow write, or one retry that a virus
// scanner forces on a just-written file, adds a few hundred milliseconds to a
// single hold of twenty and says nothing about the product, while a product
// that slows down, or always takes its slow path, slows every hold. So:
//
//   - the median hold must stay under bar on every run, unscaled: the
//     regression the bar guards moves the median, a host tail does not;
//   - the worst hold must stay under bar stretched by the host slowdown read
//     before the run (1 on an idle host, so the first run is judged on the bar
//     itself), and at most one hold of the run may be at or over bar: a host
//     tail is one hold, while a product that is slow on some of its passes
//     (a quarter of them, say) puts several holds over bar with the median
//     still under it. A run that misses either is measured again, up to
//     HoldRuns runs, each at three times the window of the one before (the
//     hookpaths recovered-parse bound does the same), so a hold that is over
//     the window in every run, or several holds over bar in every run, still
//     fails.
//
// measure runs the leg once and returns its holds. The verdict is ok with the
// holds of the run that decided it, and a one-line report of every run for the
// test log: worst, median and how many holds were over bar.
func HoldsUnderBar(bar time.Duration, measure func() []time.Duration) (holds []time.Duration, ok bool, report string) {
	slow := HostSlowdown()
	for run := 1; ; run++ {
		holds = append([]time.Duration(nil), measure()...)
		sort.Slice(holds, func(i, j int) bool { return holds[i] < holds[j] })
		if len(holds) == 0 {
			return holds, false, "no holds measured"
		}
		median, worst := holds[len(holds)/2], holds[len(holds)-1]
		over := 0
		for _, hold := range holds {
			if hold >= bar {
				over++
			}
		}
		window := Scale(bar, slow)
		line := fmt.Sprintf("run %d: hold p50 %s worst %s, %d of %d at or over %s, window %s at host slowdown x%.1f",
			run, median, worst, over, len(holds), bar, window, slow)
		report += line + "\n"
		if median >= bar {
			return holds, false, report + "the median hold is at or over the bar: every pass is slow, not one"
		}
		if worst < window && over <= 1 {
			return holds, true, report
		}
		if run == HoldRuns {
			return holds, false, report + fmt.Sprintf("in each of %d runs the worst hold was over its window or more than one hold was at or over the bar", HoldRuns)
		}
		slow = 3 * max(slow, HostSlowdown())
	}
}
