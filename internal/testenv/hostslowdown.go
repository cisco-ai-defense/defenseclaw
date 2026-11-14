// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"strconv"
	"time"
)

// ScaleEnv names the environment variable that fixes HostSlowdown for a run
// instead of measuring it: a number of at least 1, for example 4 for a host
// known to run every wall-clock window about four times slower than an idle
// one. A CI job on a starved runner sets it once for the whole shard.
const ScaleEnv = "DEFENSECLAW_TEST_TIMEOUT_SCALE"

// MaxHostSlowdown caps a measured slowdown: a host slower than this is not
// being judged on its timing at all, and a window this wide still fails a
// product that never answers.
const MaxHostSlowdown = 32.0

// HostSlowdown is how many times slower than an idle host this host runs a
// wall-clock window right now, at least 1 and at most MaxHostSlowdown. A test
// whose product bound is a wall-clock window it does not control (a judge
// timeout, an answer budget, a settle wait) multiplies its own windows by it,
// so a box starved of CPU stretches the test's tolerance and an idle one keeps
// it exact. It changes only how long a test waits: the verdict a test asserts
// is the same at every value.
//
// ScaleEnv, when set to a number of at least 1, is the answer. Otherwise it is
// the larger of two readings taken now: how long the host kept a thread that
// spun for a few milliseconds off the CPU (Measure, Linux only), and how late
// a short sleep wakes up. Each reading takes a few tens of milliseconds on an
// idle host. A reading is a moment, so a test that fails on a timing
// assertion measures again and doubles the result before it tries again.
func HostSlowdown() float64 {
	if raw := os.Getenv(ScaleEnv); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v >= 1 {
			return min(v, MaxHostSlowdown)
		}
	}
	return min(max(1, spinSlowdown(), sleepSlowdown()), MaxHostSlowdown)
}

// Scale is d stretched by a slowdown HostSlowdown gave.
func Scale(d time.Duration, slowdown float64) time.Duration {
	return time.Duration(float64(d) * max(1, slowdown))
}

// spinSlowdown spins one thread for 10 ms three times and reports the worst
// ratio of the wall time to the time the thread had the CPU.
func spinSlowdown() float64 {
	worst := 1.0
	for range 3 {
		var took time.Duration
		reading := Measure(func() {
			started := time.Now()
			for time.Since(started) < 10*time.Millisecond {
			}
			took = time.Since(started)
		})
		ran := took - reading.Denied()
		if ran <= took/MaxHostSlowdown {
			return MaxHostSlowdown
		}
		worst = max(worst, float64(took)/float64(ran))
	}
	return worst
}

// sleepSlowdown sleeps 2 ms twelve times and reports how much later the
// average sleep ended than the shortest one did. The shortest is the host's own
// timer granularity (about 2.1 ms on Linux, up to 15.6 ms on a Windows host
// with the default timer), so an idle host reads 1 on any platform, and a host
// that wakes some sleeps late reads how late.
func sleepSlowdown() float64 {
	const sleeps = 12
	var total, shortest time.Duration
	for range sleeps {
		started := time.Now()
		time.Sleep(2 * time.Millisecond)
		took := time.Since(started)
		total += took
		if shortest == 0 || took < shortest {
			shortest = took
		}
	}
	return float64(total/sleeps) / float64(max(shortest, 2*time.Millisecond))
}
